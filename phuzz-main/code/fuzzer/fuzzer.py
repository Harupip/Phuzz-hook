import argparse
import copy
import importlib
import json
import os
import random
import sys
import re
import time
import urllib.parse as urlparse
import glob
import shutil

from queue import PriorityQueue
from urllib.parse import urlencode
from itertools import product
from functools import reduce
from collections import ChainMap, Counter

import traceback
import requests
import utils
from candidate import Candidate
from mutator import DefaultMutator, EmptyQueueMutator, SingleMutator
from scoring import DefaultScoringFormula
from utils import fuzz_open
from hook_energy.seed_generation.zend_runtime.cmplog import (
    apply_cmplog_hint,
    normalize_comparison_events,
)

#def print(*args, **kwargs):
#    pass

class Fuzzer:
    def __init__(self, fuzzer_id, config_only=False):

        self.fuzzer_id = fuzzer_id
        self.start_time = int(time.time())

        self.config = None
        self.path_hashes = set()

        self.request_timeout = 5
        self.vulnerable_candidates = {}
        self.unique_vulnerable_candidates = {}
        self.exceptions_and_errors_candidates = []
        self.seen_mutations = set()
        self.trace_requests = os.environ.get("PHUZZ_TRACE_REQUESTS", "0") == "1"
        self.request_counter = 0
        self.cmplog_enabled = os.environ.get("HOOKPHUZZ_CMPLOG", "0") == "1"
        self.cmplog_hints = []
        self._cmplog_hint_keys = set()
        self.cmplog_seen_artifacts = set()

        self.session = requests.Session()
        self.login_script = None

        self.http_methods = []
        
        self.fixed_headers = {}
        self.fuzz_headers = {}
        self.weight_headers = 0.25
        
        self.fixed_cookies = {}
        self.fuzz_cookies = {}
        self.weight_cookies = 0.25

        self.fixed_query_params = {}
        self.fuzz_query_params = {}
        self.weight_query_params = 0.25

        self.fixed_body_params = {}
        self.fuzz_body_params = {}
        self.weight_body_params = 0.25

        self.coverage_files_folder = os.path.join(
            "/shared-tmpfs/", "coverage-reports")
        self.error_files_folder = os.path.join(
            "/shared-tmpfs/", "error-reports")
        self.exception_files_folder = os.path.join(
            "/shared-tmpfs/", "exception-reports"
        )
        self.mysql_errors_folder = os.path.join(
            "/shared-tmpfs/", "mysql-error-reports")
        self.shell_errors_folder = os.path.join(
            "/shared-tmpfs/", "shell-error-reports")
        self.unserialize_errors_folder = os.path.join(
            "/shared-tmpfs/", "unserialize-error-reports")
        self.pathtraversal_errors_folder = os.path.join(
            "/shared-tmpfs/", "pathtraversal-error-reports")
        self.xxe_errors_folder = os.path.join(
            "/shared-tmpfs/", "xxe-error-reports")
        self.output_dir = os.path.join("./output", f"fuzzer-{fuzzer_id}")
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.mkdir(self.output_dir)

        ### 
        # BEGIN Define Fuzzing modules
        ####
        self.scoring_formula = DefaultScoringFormula()
        self.mutator = DefaultMutator()
        self.vulnchecker = None
        if not config_only:
            from vulncheck import ParamBasedVulnChecker
            self.vulnchecker = ParamBasedVulnChecker(
                mysql_errors_folder=self.mysql_errors_folder,
                shell_errors_folder=self.shell_errors_folder,
                unserialize_errors_folder=self.unserialize_errors_folder,
                pathtraversal_errors_folder=self.pathtraversal_errors_folder,
                xxe_errors_folder=self.xxe_errors_folder,
            )
        ### 
        # END Define Fuzzing modules
        ####
        os.umask(0)

    def _open(self, filepath):
        return os.open(filepath, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o777)

    def _short_repr(self, value, limit=120):
        text = repr(value)
        if len(text) > limit:
            return text[: limit - 3] + "..."
        return text

    def _trace_request(self, candidate, prepared_req=None, response=None, error=None):
        if not self.trace_requests:
            return

        self.request_counter += 1
        parts = [f"[req {self.request_counter}]"]

        if prepared_req is not None:
            parts.append(prepared_req.method)
            parts.append(prepared_req.url)
        else:
            parts.append(candidate.http_method)
            parts.append(candidate.http_target)

        if candidate.mutated_param_type and candidate.mutated_param_name:
            mutated_value = candidate.fuzz_params.get(
                candidate.mutated_param_type, {}
            ).get(candidate.mutated_param_name)
            parts.append(
                f"mutated={candidate.mutated_param_type}.{candidate.mutated_param_name}"
            )
            parts.append(f"value={self._short_repr(mutated_value)}")
        elif candidate.is_initial_candidate:
            parts.append("candidate=initial")

        parts.append(f"mutation_source={getattr(candidate, 'mutation_source', 'normal')}")

        if response is not None:
            parts.append(f"status={response.status_code}")
            parts.append(f"bytes={len(response.text)}")

        if error is not None:
            parts.append(f"error={self._short_repr(str(error))}")

        print(" ".join(parts))

    def _ingest_cmplog_hints(self, candidate):
        """Normalize one completed Zend artifact before the next mutation."""
        if not self.cmplog_enabled:
            return
        artifact_path = os.path.join(
            "/shared", "opcode-events", f"{candidate.coverage_id}.json"
        )
        if artifact_path in self.cmplog_seen_artifacts or not os.path.exists(artifact_path):
            return
        self.cmplog_seen_artifacts.add(artifact_path)
        try:
            with fuzz_open(artifact_path, "r") as artifact_file:
                artifact = json.load(artifact_file)
        except (OSError, ValueError):
            return
        for hint in normalize_comparison_events(artifact, candidate.fuzz_params):
            hint_key = json.dumps(hint, sort_keys=True, default=str)
            if hint_key in self._cmplog_hint_keys:
                continue
            self._cmplog_hint_keys.add(hint_key)
            self.cmplog_hints.append(hint)

    def save_output_vulnerable(self):
        with open(
            self._open(
                os.path.join(
                    self.output_dir,
                    f"vulnerable-candidates.json",
                )
            ),
            "w",
        ) as f:
            json.dump(self.vulnerable_candidates, f, default=lambda x:x.__dict__(), indent=2)

        pathmap = {
            'SQLi': self.mysql_errors_folder,
            'CommandInjection': self.shell_errors_folder,
            'Unserialize': self.unserialize_errors_folder,
            'PathTraversal': self.pathtraversal_errors_folder,
            'XXE': self.xxe_errors_folder
        }

        for k in self.vulnerable_candidates:
            if not k in pathmap:
                continue
            for candidate in self.vulnerable_candidates[k]:
                vuln_info_file = os.path.join(pathmap[k], f"{candidate.coverage_id}.json")
                if not os.path.exists(vuln_info_file):
                    continue
                shutil.copyfile(vuln_info_file, os.path.join(self.output_dir, f"{k}-{candidate.coverage_id}.json"))

        print("Vulnerable candidates saved!")

    def save_output_exceptions_errors(self):
        with open(
            self._open(
                os.path.join(
                    self.output_dir,
                    f"exceptions-and-errors.json",
                )
            ),
            "w",
        ) as f:
            json.dump(self.exceptions_and_errors_candidates, f, default=lambda x: x.__dict__(), indent=2)

        for candidate in self.exceptions_and_errors_candidates:
            exception_path = os.path.join(self.exception_files_folder, f"{candidate.coverage_id}.json")
            error_path = os.path.join(self.error_files_folder, f"{candidate.coverage_id}.json")

            if os.path.exists(exception_path):
                shutil.copyfile(exception_path, os.path.join(self.output_dir, f"exception-{candidate.coverage_id}.json"))
            
            if os.path.exists(error_path):
                shutil.copyfile(error_path, os.path.join(self.output_dir, f"error-{candidate.coverage_id}.json"))

        print("Exceptions and errors candidates saved!")

    def load_request_data(self):
        potential = {}
        potential['methods'] = []
        potential['headers'] = []
        potential['cookies'] = []
        potential['query_params'] = []
        potential['body_params'] = []

        if 'request_timeout' in self.config:
            self.request_timeout = float(self.config['request_timeout'])

        if 'har_input' in self.config:
            # we only look at the first request in the HAR file
            har_request = utils.extract_input_vectors_from_har(
                f"./resources/har_{self.config['har_input']}.har"
            )[0]

            potential['methods'].append(har_request.get("method", "GET"))
            potential['headers'] += har_request.get("headers", [])
            potential['cookies'] += har_request.get("cookies", [])
            potential['query_params'] += har_request.get("query_string", [])
            potential['body_params'] += har_request.get("form_data", [])
            # These are {'name': 'value'}-pairs

        if 'methods' in self.config:
            potential['methods'] += self.config['methods']

        self.http_methods = list(set(potential['methods']))

        # Make sure that 'print_timestamps' is set
        self.config['print_timestamps'] = self.config.get('print_timestamps', False)

        if "login" in self.config and self.config["login"] and not self._disable_auth_cookies():
            login_cookies = self.login()
            for k,v in login_cookies.items():
                if 'cookies' in self.config and 'login' in self.config['cookies']:
                    for regex in self.config['cookies']['login']:
                        if re.match(regex, k):
                            potential['cookies'].append({'name': k, 'value': v})
                else:
                    potential['cookies'].append({'name': k, 'value': v})

        for config_key in ['headers', 'cookies', 'query_params', 'body_params']:
            if not config_key in self.config:
                continue

            if "data" in self.config[config_key]:
                potential[config_key] += self.config[config_key]['data']
            else:
                raise Exception(f"Config parsing error: No parameters specified with 'data' for {config_key}")

            if 'weight' in self.config[config_key]:
                setattr(self, f"weight_{config_key}", self.config[config_key]['weight'])

        # now filter/assign these to fixed/fuzz params
        for config_key in ['headers', 'cookies', 'query_params', 'body_params']:
            # Fixed params need a {'name': name, 'value': value} dict!
            fixed_dict = getattr(self,f"fixed_{config_key}",{})
            #print("fixed dict init: ", fixed_dict)
            if config_key in self.config and 'fixed' in self.config[config_key] and self.config[config_key]['fixed']:
                for regex in self.config[config_key]['fixed']:
                    r = re.compile(regex)
                    for param in potential[config_key]:
                        param_name = param['name']
                        if r.match(param_name):
                            if not param_name in fixed_dict:
                                fixed_dict[param_name] = []
                            if 'value' in param:
                                if param['value'] not in fixed_dict[param_name]:
                                    fixed_dict[param_name].append(param['value'])
                            elif 'seeds' in param:
                                for value in param['seeds']:
                                    if value not in fixed_dict[param_name]:
                                        fixed_dict[param_name].append(value)
                            else:
                                raise Exception(f"Neither seeds nor value for param {param_name}")

            fuzz_dict = getattr(self,f"fuzz_{config_key}",{})

            #print("fuzz dict init: ", fuzz_dict)
            if config_key in self.config and 'fuzz' in self.config[config_key] and self.config[config_key]['fuzz']:
                for regex in self.config[config_key]['fuzz']:
                    r = re.compile(regex)
                    for param in potential[config_key]:
                        param_name = param['name']
                        # Ignore fixed params that we have already set.
                        if param_name in fixed_dict:
                            continue
                        if config_key == 'headers' and param_name.lower() in ["host", "cookie"]:
                            continue
                        if r.match(param_name):
                            if not param_name in fuzz_dict:
                                fuzz_dict[param_name] = []
                            if 'value' in param:
                                if param['value'] not in fuzz_dict[param_name]:
                                    fuzz_dict[param_name].append(param['value'])
                            elif 'seeds' in param:
                                for value in param['seeds']:
                                    if value not in fuzz_dict[param_name]:
                                        fuzz_dict[param_name].append(value)
                            else:
                                raise Exception(f"Neither seeds nor value for param {param_name}")
            else:
                # Fuzz all by default
                for param in potential[config_key]:
                    param_name = param['name']
                    # Ignore fixed params that we have already set.
                    if param_name in fixed_dict:
                        continue
                    if config_key == 'headers' and param_name.lower() in ["host", "cookie"]:
                        continue
                    if not param_name in fuzz_dict:
                        fuzz_dict[param_name] = []
                    if 'value' in param:
                        if param['value'] not in fuzz_dict[param_name]:
                            fuzz_dict[param_name].append(param['value'])
                    elif 'seeds' in param:
                        for value in param['seeds']:
                            if value not in fuzz_dict[param_name]:
                                fuzz_dict[param_name].append(value)
                    else:
                        raise Exception(f"Neither seeds nor value for param {param_name}")


            for k in fixed_dict:
                fixed_dict[k] = list(fixed_dict[k])
            for k in fuzz_dict:
                fuzz_dict[k] = list(fuzz_dict[k])
            setattr(self, f"fuzz_{config_key}", fuzz_dict)
            setattr(self, f"fixed_{config_key}", fixed_dict)

    def load_config(self, config_path, config_dir="./configs"):
        try:
            self.config = json.load(
                open(os.path.join(config_dir, f"{config_path}.json"))
            )
        except Exception as e:
            print(e)
            sys.exit(f"Failed to parse fuzzer config: {config_path}")

        if not self.config["target"].startswith("http"):
            sys.exit(f"Target does not start with http!")

        if "login" in self.config and not os.path.exists(
            os.path.join("./automated_logins", f"{self.config['login']}.py")
        ):
            sys.exit(f"Login file {self.config['login']} does not exist.")

    def login(self):
        login_script = importlib.import_module(
            f"automated_logins.{self.config['login']}"
        )
        login_script.main()
        print("Ran login script")
        login_cookies = json.load(
            open(
                os.path.join(
                    "/shared-tmpfs", f"cookies_node{os.environ['FUZZER_NODE_ID']}.json"
                ),
                "r",
            )
        )

        print("Found login cookies", login_cookies)
        return login_cookies

    def _param_tuple_to_dict(self, tpl):
        return dict(ChainMap(*list(map(lambda x: {x['name']: x['value']}, tpl))))

    def generate_initial_candidates(self):

        print("Fixed headers", self.fixed_headers)
        print("Fixed Cookies", self.fixed_cookies)
        print("Fixed Query Params", self.fixed_query_params)
        print("Fixed Body Params", self.fixed_body_params)

        print("Fuzz headers", self.fuzz_headers)
        print("Fuzz cookies", self.fuzz_cookies)
        print("Fuzz query params", self.fuzz_query_params)
        print("Fuzz body params", self.fuzz_body_params)

        fixed_generators = {}
        fuzz_generators = {}

        for keyword in ['headers', 'cookies', 'query_params', 'body_params']:
            fixed_dict = getattr(self, f"fixed_{keyword}", {})
            keyword_comb = []
            for k in fixed_dict:
                tmp_list = []
                for v in fixed_dict[k]:
                    tmp_list.append({'name': k, 'value': v})
                keyword_comb.append(tmp_list)

            fixed_generators[keyword] = list(product(*keyword_comb))

            fuzz_dict = getattr(self, f"fuzz_{keyword}", {})
            #print("fuzz dict: ", fuzz_dict)
            keyword_comb = []
            for k in fuzz_dict:
                tmp_list = []
                for v in fuzz_dict[k]:
                    tmp_list.append({'name': k, 'value': v})
                keyword_comb.append(tmp_list)

            fuzz_generators[keyword] = list(product(*keyword_comb))

        for req_method in self.http_methods:
            for fixed_header_comb in fixed_generators['headers']:
                for fixed_cookie_comb in fixed_generators['cookies']:
                    for fixed_query_params_comb in fixed_generators['query_params']:
                        for fixed_body_params_comb in fixed_generators['body_params']:
                            for fuzz_header_comb in fuzz_generators['headers']:
                                for fuzz_cookie_comb in fuzz_generators['cookies']:
                                    for fuzz_query_params_comb in fuzz_generators['query_params']:
                                        for fuzz_body_params_comb in fuzz_generators['body_params']:

                                            c = Candidate(
                                                score=100,
                                                priority=100,
                                                http_target=self.config['target'],
                                                http_method=req_method,
                                                is_initial_candidate=True,
                                                fixed_params={
                                                    'headers': self._param_tuple_to_dict(fixed_header_comb),
                                                    'cookies': self._param_tuple_to_dict(fixed_cookie_comb),
                                                    'query_params': self._param_tuple_to_dict(fixed_query_params_comb),
                                                    'body_params': self._param_tuple_to_dict(fixed_body_params_comb)
                                                },
                                                fuzz_params={
                                                    'headers': self._param_tuple_to_dict(fuzz_header_comb),
                                                    'cookies': self._param_tuple_to_dict(fuzz_cookie_comb),
                                                    'query_params': self._param_tuple_to_dict(fuzz_query_params_comb),
                                                    'body_params': self._param_tuple_to_dict(fuzz_body_params_comb)
                                                },
                                                fuzz_weights={
                                                    'headers': self.weight_headers,
                                                    'cookies': self.weight_cookies,
                                                    'query_params': self.weight_query_params,
                                                    'body_params': self.weight_body_params
                                                },
                                                fuzzer_id=self.fuzzer_id,
                                                #is_initial_candidate=True
                                                )
                                            yield c


    def calculate_score(self, candidate):
        # Outer wrapper: the fuzz loop calls this after coverage is collected.
        score = self.scoring_formula.calculate_score(candidate)
        candidate.score = score
        return score

    def calculate_priority(self, candidate):
        # Outer wrapper: queue ordering uses the priority written here.
        priority = self.scoring_formula.calculate_priority(candidate)
        candidate.priority = priority
        return priority

    def calculate_energy(self, c):
        # Outer wrapper: after parent selection, delegate to the scoring formula for the final mutate budget.
        return self.scoring_formula.calculate_energy(c)

    def cleanup(self, candidate):
        coverage_file_path = os.path.join(
            self.coverage_files_folder, f"{candidate.coverage_id}.json"
        )

        if os.path.exists(coverage_file_path):
            os.unlink(coverage_file_path)

    def check_for_exception_or_error(self, candidate):
        exception_file = os.path.join(
            self.exception_files_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.exists(exception_file):
            candidate.exceptions = []
            for line in fuzz_open(exception_file, "r"):
                if line.strip():
                    candidate.exceptions.append(json.loads(line))

        error_file = os.path.join(
            self.error_files_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.exists(error_file):
            candidate.errors = []
            for line in fuzz_open(error_file, "r"):
                if line.strip():
                    candidate.errors.append(json.loads(line))


        if candidate.errors or candidate.exceptions:
            print(
                f"\033[91mFound an error or exception with candidate: {candidate.exceptions} // {candidate.errors}\033[0m")
            return True
        else:
            return False

    def prepare_request(self, candidate):
        base_url = candidate.http_target

        # based on https://stackoverflow.com/a/2506477
        url_parts = list(urlparse.urlparse(base_url))
        query = dict(urlparse.parse_qsl(url_parts[4]))
        url_parts[4] = '' # reset query string, which we will set using params={...}

        the_params = {**query, **candidate.fuzz_params['query_params'], **candidate.fixed_params['query_params']}
        the_body_params = {**candidate.fuzz_params['body_params'], **candidate.fixed_params['body_params']}
        the_cookies = {**candidate.fuzz_params['cookies'], **candidate.fixed_params['cookies']} # self._urlencode_dict()
        if self._disable_auth_cookies():
            the_cookies = self._without_auth_cookies(the_cookies)
        the_headers = {**candidate.fuzz_params['headers'], **candidate.fixed_params['headers']}
        the_headers["X-Fuzzer-Covid"] = candidate.coverage_id
        the_headers["X-HookPhuzz-Request-ID"] = candidate.coverage_id
        legacy_run_id = os.environ.get("HOOKPHUZZ_LEGACY_RUN_ID", "")
        if legacy_run_id:
            the_headers.setdefault("X-HookPhuzz-Run-ID", legacy_run_id)

        # print({
        #     'query': the_params,
        #     'cookies': the_cookies,
        #     'headers': the_headers,
        #     'body': the_body_params    
        #     })

        if candidate.http_method in ["GET", "OPTIONS", "TRACE"]:
            req = requests.Request(method=candidate.http_method, 
                                    url=urlparse.urlunparse(url_parts),
                                    params=the_params,
                                    cookies=the_cookies,
                                    headers=the_headers)

        elif candidate.http_method in ["POST", "PUT", "PATCH", "DELETE"]:
            content_type = the_headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
            if content_type == 'application/json':
                req = requests.Request(method=candidate.http_method, 
                                    url=urlparse.urlunparse(url_parts),
                                    params=the_params,
                                    cookies=the_cookies,
                                    headers=the_headers,
                                    json=the_body_params)
            else:
                req = requests.Request(method=candidate.http_method, 
                                    url=urlparse.urlunparse(url_parts),
                                    params=the_params,
                                    cookies=the_cookies,
                                    headers=the_headers,
                                    data=the_body_params)

        else:
            raise Exception("Unknown HTTP method!")

        prepared = req.prepare()

        return prepared

    def _disable_auth_cookies(self):
        metadata = self.config.get("metadata") if isinstance(self.config, dict) else {}
        if not isinstance(metadata, dict):
            metadata = {}
        auth_mode = str(metadata.get("auth_mode") or self.config.get("auth_mode") or "").strip().lower()
        if auth_mode in {"unauth-capable", "unauthenticated", "nopriv", "public"}:
            return True
        if auth_mode in {"authenticated", "auth"}:
            return False
        hook_name = str(metadata.get("hook_name") or self.config.get("hook_name") or "")
        return hook_name.startswith("wp_ajax_nopriv_")

    def _without_auth_cookies(self, cookies):
        return {
            name: value for name, value in cookies.items()
            if not str(name).startswith(("wordpress_logged_in_", "wordpress_sec_"))
        }

    def run(self):
        self.load_request_data()
        if self.config['print_timestamps']:
            print(f"START_TIME: {time.time()}")
        self.fuzz_fast()



    def ff_choose_next(self, offset):
        if self.ff_interesting_candidates:
            #print("interesting: ", [(x.priority, x.score) for x in sorted(self.ff_interesting_candidates)])
            c = sorted(self.ff_interesting_candidates)[-1 -(offset % len(self.ff_interesting_candidates))]
        else:
            #print("normal: ", [(x.priority, x.score) for x in sorted(self.ff_candidates)])
            c = sorted(self.ff_candidates)[-1 -(offset % len(self.ff_candidates))]

        #print("We chose: ", (c.priority, c.score), "offset: ", offset)

        return c


    def ff_mutate(self, c):

        while self.cmplog_hints:
            hint = self.cmplog_hints.pop(0)
            applied = apply_cmplog_hint(c.fuzz_params, hint)
            if applied is None:
                continue
            return Candidate(
                parent=c,
                priority=self.scoring_formula.calculate_priority(c),
                http_target=c.http_target,
                http_method=c.http_method,
                fixed_params=copy.deepcopy(c.fixed_params),
                fuzz_params=applied["fuzz_params"],
                fuzz_weights=copy.deepcopy(c.fuzz_weights),
                fuzzer_id=self.fuzzer_id,
                mutated_param_type=applied["mutated_param_type"],
                mutated_param_name=applied["mutated_param_name"],
                mutation_source=applied["mutation_source"],
                cmplog_hint=applied["cmplog_hint"],
            )

        mutator = SingleMutator()

        choice_keys = list(filter(lambda x: c.fuzz_params[x], c.fuzz_params))
        choice_weights = list(map(lambda x: c.fuzz_weights[x], choice_keys))
        if not choice_keys or not choice_weights:
            return None
        param_type = random.choices(choice_keys, weights=choice_weights)[0]
        param_name = random.choice(list(c.fuzz_params[param_type].keys()))

        param_value = c.fuzz_params[param_type][param_name]
        new_value = mutator.mutate(param_value)

        fuzz_params = copy.deepcopy(c.fuzz_params)
        fuzz_params[param_type][param_name] = new_value
        new_candidate = Candidate(
            parent=c,
            priority=self.scoring_formula.calculate_priority(c),
            http_target=c.http_target,
            http_method=c.http_method,
            fixed_params=copy.deepcopy(c.fixed_params),
            fuzz_params=fuzz_params,
            fuzz_weights=copy.deepcopy(c.fuzz_weights),
            fuzzer_id=self.fuzzer_id,
            mutated_param_type=param_type,
            mutated_param_name=param_name
            )

        return new_candidate

    def ff_send_request(self, c):
        prepared_req = None
        try:
            with requests.Session() as s:
                # Optional request-level tracing for plugin/debug runs.
                prepared_req = self.prepare_request(c)
                response = s.send(prepared_req, timeout=self.request_timeout, allow_redirects=False)
                c.response = response
                self._trace_request(c, prepared_req=prepared_req, response=response)
        except Exception as e:
            self._trace_request(c, prepared_req=prepared_req, error=e)
            print(f"Exception encountered: {e}")
            c.response = None

    def ff_has_vulns(self, c):
        vulns = self.vulnchecker.vuln_check(c)
        if any(vulns):
            for k in vulns:
                if self.config['print_timestamps']:
                    print(f"{k.upper()}_TIME: {time.time()}")
                if not k in self.vulnerable_candidates:
                    self.vulnerable_candidates[k] = []
                    self.unique_vulnerable_candidates[k] = set()
                self.vulnerable_candidates[k].append(c)
                if k not in c.vulns:
                    c.vulns.append(k)

                vuln_id = c.get_paths_hash()
                if not vuln_id in self.unique_vulnerable_candidates[k]:
                    self.unique_vulnerable_candidates[k].add(vuln_id)

                print(
                    f"{k}: {len(self.vulnerable_candidates[k])} ({len(self.unique_vulnerable_candidates[k])})"
                )
            self.save_output_vulnerable()
            print("Found vulns!")
            c.print_candidate_info()
            return True
        else:
            return False

    def ff_is_interesting(self, c):
        if c.number_of_new_paths > 0:
            cph = c.get_paths_hash()
            if cph in self.path_hashes:
                return False
            print(f"\033[92mNew paths found: {c.new_paths}\033[0m\n")
            c.is_interesting = True
            self.path_hashes.add(cph)
            return True
        return False

    def ff_has_exceptions(self, c):
        error = self.check_for_exception_or_error(c)

        if error:
            self.exceptions_and_errors_candidates.append(c)
            self.save_output_exceptions_errors()
            return True
        else:
            return False

    def ff_get_coverage(self, candidate):
        coverage_file_path = (
            f"{self.coverage_files_folder}/{candidate.coverage_id}.json"
        )
        if not os.path.exists(coverage_file_path):
            return 0

        with fuzz_open(coverage_file_path, "r") as f:
            coverage_report = json.load(f)

        if not coverage_report:
            return 0

        hit_paths = utils.extract_hit_paths(coverage_report)
        stringified_hit_paths = set(utils.stringify_hit_paths(hit_paths))

        hit_path_set = set(stringified_hit_paths)

        if candidate.parent:
            parent_paths=set(candidate.parent.paths)
        else:
            parent_paths=set()

        new_paths = hit_path_set.difference(parent_paths) # (self.paths | hit_path_set) - self.paths
        number_of_new_paths = len(new_paths)
        # self.paths.update(hit_path_set)

        candidate.paths = list(stringified_hit_paths | parent_paths)
        candidate.new_paths = new_paths
        candidate.number_of_new_paths = number_of_new_paths

    def ff_sync_candidates(self):
        sync_path = "/sync-tmpfs/"

        file_hashes = set(map(lambda x: x.replace(sync_path,"").replace(".json", ""), glob.glob(sync_path + "[a-z0-9]*.json")))

        new_hashes = file_hashes.difference(self.seen_mutations)

        counter_total = 0
        counter_added = 0
        counter_interesting = 0

        for h in new_hashes:
            if 'interesting_' in h:
                h = h.replace("interesting_", "")

            c = self.ff_load_candidate(h)
            chash = c.get_params_hash()
            if chash not in self.seen_mutations:
                self.seen_mutations.add(chash)
                self.ff_candidates.append(c)
                counter_added += 1
            if c.is_interesting and chash not in self.ff_interesting_candidates_hashes:
                self.ff_interesting_candidates_hashes.add(chash)
                self.ff_interesting_candidates.append(c)
                counter_interesting +=1
            counter_total += 1
        return counter_total, counter_added, counter_interesting

    def ff_load_candidate(self, chash):
        c = Candidate()
        c.load_sync_file(candidate_hash=chash)
        self.ff_reset_cookies(c)
        # self.paths.update(c.paths)
        return c

    def ff_reset_cookies(self, candidate):
        if 'cookies' in self.config and 'login' in self.config['cookies']:
            lcrs = self.config['cookies']['login']
        else:
            lcrs = []

        for r in lcrs:
            for k,v in self.fixed_cookies.items():
                if re.match(r, k):
                    candidate.fixed_params['cookies'][k] = v[0] # Always use the first value

    def fuzz_fast(self):
        counter = 0

        self.ff_candidates = [] 
        # Th is self.seen_mutations
        self.ff_interesting_candidates = []
        self.ff_interesting_candidates_hashes = set()
        self.ff_vulnerable_candidates = []

        # Send initial requests first
        for c in self.generate_initial_candidates():
            self.ff_send_request(c)
            self._ingest_cmplog_hints(c)
            counter += 1
            self.ff_get_coverage(c)
            self.calculate_score(c)
            self.calculate_priority(c)
            if self.ff_is_interesting(c):
                self.ff_interesting_candidates.append(c)
                self.ff_interesting_candidates_hashes.add(c.get_params_hash())
            self.ff_candidates.append(c)
            self.seen_mutations.add(c.get_params_hash())

        sync_total, sync_new, sync_interesting = self.ff_sync_candidates()
        print("Synced new candidates (total / new / interesting): ", sync_total, sync_new, sync_interesting)

        choose_offset = 0
        round_time = time.time()
        while True:
            sync_total, sync_new, sync_interesting = self.ff_sync_candidates()
            #print("Synced new candidates (total / new / interesting): ", sync_total, sync_new, sync_interesting)

            candidate = self.ff_choose_next(choose_offset)
            choose_offset += 1
            candidate_hash = candidate.get_params_hash()
            #print("Candidate priority / score: ", candidate.priority, candidate.score, candidate_hash, candidate.fuzz_params)

            # This is the handoff from score/priority land into scheduler budget.
            energy = self.calculate_energy(candidate)
            #print(energy)
            # This loop is where integer `energy` becomes actual mutation attempts.
            for i in range(energy):
                if os.path.exists("/sync-tmpfs/vuln_found"):
                    sys.exit(1337)

                mutated_candidate = self.ff_mutate(candidate)
                if not mutated_candidate:
                    continue
                mutated_candidate_hash = mutated_candidate.get_params_hash()

                #print("Mutation: ", mutated_candidate_hash, mutated_candidate.fuzz_params)
                if mutated_candidate_hash in self.seen_mutations:
                    continue
                else:
                    self.seen_mutations.add(mutated_candidate_hash)

                if os.path.exists(mutated_candidate.get_sync_file()):
                    mutated_candidate = self.ff_load_candidate(mutated_candidate_hash)
                    if mutated_candidate.is_interesting and mutated_candidate_hash not in self.ff_interesting_candidates_hashes:
                        self.ff_interesting_candidates.append(mutated_candidate)
                        self.ff_interesting_candidates_hashes.add(mutated_candidate_hash)
                    continue

                self.ff_send_request(mutated_candidate)
                self._ingest_cmplog_hints(mutated_candidate)
                counter += 1

                if counter % 100 == 0:
                    time_diff = time.time() - round_time
                    #print(
                    #    f"Performance: {time_diff}s for 0.1k reqs -> {1.0/(time_diff/100)} reqs/s"
                    #)
                    round_time = time.time()

                self.ff_get_coverage(mutated_candidate)
                self.calculate_score(mutated_candidate)
                self.calculate_priority(mutated_candidate)


                if self.ff_has_exceptions(mutated_candidate):
                    pass

                if self.ff_has_vulns(mutated_candidate):
                    self.ff_vulnerable_candidates.append(mutated_candidate)

                    for vuln_type in mutated_candidate.vulns:
                        stop = int(time.time())
                        diff = stop - self.start_time
                        print(f"\n\n\n\n\n\nFound {vuln_type}! in {diff}s\n\n\n\n\n\n")
                        with open("/sync-tmpfs/vuln_found", "w") as f:
                            f.write(f"Found by {self.fuzzer_id} in {diff}s")
                        sys.exit(1337) #TODO: comment me out!

                if self.ff_is_interesting(mutated_candidate):
                    #print("TP priority / score:", mutated_candidate.priority, mutated_candidate.score)
                    self.ff_interesting_candidates.append(mutated_candidate)
                    self.ff_interesting_candidates_hashes.add(mutated_candidate_hash)
                    if mutated_candidate.mutated_param_type and mutated_candidate.mutated_param_name:
                        fixed_params = copy.deepcopy(mutated_candidate.fixed_params)
                        fuzz_params = copy.deepcopy(mutated_candidate.fuzz_params)
                        fuzz_weights = copy.deepcopy(mutated_candidate.fuzz_weights)

                        fixed_params[mutated_candidate.mutated_param_type][mutated_candidate.mutated_param_name] = mutated_candidate.fuzz_params[mutated_candidate.mutated_param_type][mutated_candidate.mutated_param_name]
                        del fuzz_params[mutated_candidate.mutated_param_type][mutated_candidate.mutated_param_name]
                        if not fuzz_params[mutated_candidate.mutated_param_type]:
                            del fuzz_weights[mutated_candidate.mutated_param_type]

                        new_candidate = Candidate(
                            parent=mutated_candidate.parent,
                            score=mutated_candidate.parent.score,
                            priority=mutated_candidate.parent.priority,
                            http_target=mutated_candidate.http_target,
                            http_method=mutated_candidate.http_method,
                            fixed_params=fixed_params,
                            fuzz_params=fuzz_params,
                            fuzz_weights=fuzz_weights,
                            fuzzer_id=self.fuzzer_id
                            )
                        #print("NEW params: ", new_candidate.fuzz_params, "with prio:", new_candidate.priority)
                        self.ff_interesting_candidates.append(new_candidate)
                        self.ff_interesting_candidates_hashes.add(new_candidate.get_params_hash())
                    choose_offset = 0

                mutated_candidate.write_sync_file()
                if os.environ["FUZZER_CLEANUP"] == "1":
                    self.cleanup(mutated_candidate)


if __name__ == "__main__":
    #time.sleep(10)

    if "FUZZER_SEED" in os.environ:
        random_seed = int(os.environ["FUZZER_SEED"])
    else:
        random_seed = int.from_bytes(os.urandom(4), byteorder="little")
    random.seed(random_seed)

    if not "FUZZER_NODE_ID" in os.environ:
        os.environ["FUZZER_NODE_ID"] = "1"

    if not "FUZZER_CLEANUP" in os.environ:
        os.environ["FUZZER_CLEANUP"] = "1"

    if not "FUZZER_COMPRESS" in os.environ:
        os.environ["FUZZER_COMPRESS"] = "0"

    if not "FUZZER_CONFIG" in os.environ:
        sys.exit("No config provided in ENV FUZZER_CONFIG")

    fuzzer = Fuzzer(fuzzer_id=os.environ['FUZZER_NODE_ID'])
    fuzzer.load_config(os.environ['FUZZER_CONFIG'])
    fuzzer.run()
