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
from collections import ChainMap, Counter, OrderedDict

import traceback
import requests
from core import utils
from core.candidate import Candidate, sync_dir
from core.mutator import DefaultMutator, EmptyQueueMutator, SingleMutator
from core.scoring import DefaultScoringFormula, phuzz_base_energy
from core.utils import fuzz_open
from core.finding_artifact import build_finding_record, write_finding_artifact
from core import online_handoff as handoff
from core.online_handoff import PauseGate

# Config root inside the worker container; HOOKPHUZZ_PRIORITY_SEED names a replay config below it.
PRIORITY_CONFIG_DIR = "./configs"
from fuzz_guidance.cmplog.hints import (
    apply_cmplog_hint,
    normalize_comparison_events,
)

#def print(*args, **kwargs):
#    pass


def _request_auth_context_from_config(config):
    metadata = config.get('metadata') or {}
    hook = str(metadata.get('hook_name') or config.get('hook_name') or '')
    entrypoint = str(config.get('entrypoint_type') or metadata.get('entrypoint_type') or '')
    if (hook.startswith(('wp_ajax_nopriv_', 'admin_post_nopriv_'))
            or hook == 'heartbeat_nopriv_received'
            or entrypoint in {'ajax_unauthenticated', 'admin_post_unauthenticated'}):
        return 'guest'
    context = metadata.get('auth_context', 'authenticated')
    if context not in {'guest', 'authenticated'}:
        raise ValueError('unsupported auth_context')
    return context


def _disable_auth_cookies_from_config(config):
    if _request_auth_context_from_config(config) == 'guest':
        return True
    metadata = config.get('metadata') if isinstance(config, dict) else {}
    if not isinstance(metadata, dict):
        metadata = {}
    auth_mode = str(metadata.get('auth_mode') or config.get('auth_mode') or '').strip().lower()
    if auth_mode in {'unauth-capable', 'unauthenticated', 'nopriv', 'public'}:
        return True
    if auth_mode in {'authenticated', 'auth'}:
        return False
    hook_name = str(metadata.get('hook_name') or config.get('hook_name') or '')
    return hook_name.startswith('wp_ajax_nopriv_')


def _without_auth_cookies(cookies):
    return {
        name: value for name, value in cookies.items()
        if not (str(name).startswith('wordpress_') and str(name) != 'wordpress_test_cookie')
    }


def _prepare_request(
    config, *, base_url, http_method, fuzz_params, fixed_params, request_id, run_id,
    force_run_id=False,
):
    url_parts = list(urlparse.urlparse(base_url))
    query = dict(urlparse.parse_qsl(url_parts[4]))
    url_parts[4] = ''

    the_params = {**query, **fuzz_params['query_params'], **fixed_params['query_params']}
    the_body_params = {**fuzz_params['body_params'], **fixed_params['body_params']}
    the_cookies = {**fuzz_params['cookies'], **fixed_params['cookies']}
    if _disable_auth_cookies_from_config(config):
        the_cookies = _without_auth_cookies(the_cookies)
    the_headers = {**fuzz_params['headers'], **fixed_params['headers']}
    auth_context = _request_auth_context_from_config(config)
    the_headers = {name: value for name, value in the_headers.items()
                   if name.lower() != 'x-hookphuzz-auth-context'
                   and not (auth_context == 'guest' and name.lower() == 'cookie')}
    the_headers['X-HookPhuzz-Auth-Context'] = auth_context
    the_headers['X-Fuzzer-Covid'] = request_id
    the_headers['X-HookPhuzz-Request-ID'] = request_id
    if run_id:
        if force_run_id:
            the_headers['X-HookPhuzz-Run-ID'] = run_id
        else:
            the_headers.setdefault('X-HookPhuzz-Run-ID', run_id)

    if http_method in ['GET', 'OPTIONS', 'TRACE']:
        req = requests.Request(method=http_method, url=urlparse.urlunparse(url_parts),
                                params=the_params, cookies=the_cookies, headers=the_headers)
    elif http_method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        content_type = the_headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
        kwargs = {'method': http_method, 'url': urlparse.urlunparse(url_parts),
                  'params': the_params, 'cookies': the_cookies, 'headers': the_headers}
        if content_type == 'application/json':
            kwargs['json'] = the_body_params
        else:
            kwargs['data'] = the_body_params
        req = requests.Request(**kwargs)
    else:
        raise Exception('Unknown HTTP method!')
    return req.prepare()


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
        try:
            self.stop_on_vuln_count = int(os.environ.get("HOOKPHUZZ_STOP_ON_VULN", "0"))
        except ValueError as exc:
            raise ValueError("HOOKPHUZZ_STOP_ON_VULN must be a non-negative integer") from exc
        if self.stop_on_vuln_count < 0:
            raise ValueError("HOOKPHUZZ_STOP_ON_VULN must be a non-negative integer")
        self.vulnerability_count = 0
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
        self.output_dir = os.path.join("./output", "workers", f"fuzzer-{fuzzer_id}")
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir, exist_ok=True)

        ### 
        # BEGIN Define Fuzzing modules
        ####
        self.scoring_formula = DefaultScoringFormula()
        self.mutator = DefaultMutator()
        self.vulnchecker = None
        if not config_only:
            from core.vulncheck import ParamBasedVulnChecker
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
        if not isinstance(artifact, dict) or artifact.get("request_id") != candidate.coverage_id:
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

        run_id = os.environ.get("HOOKPHUZZ_LEGACY_RUN_ID", "") or f"fuzzer-{self.fuzzer_id}-{self.start_time}"
        finding_records = []
        for vuln_type, candidates in self.vulnerable_candidates.items():
            for candidate in candidates:
                finding_records.append(
                    build_finding_record(candidate, vuln_type=vuln_type, run_id=run_id)
                )

        finding_path = os.environ.get("HOOKPHUZZ_FINDING_ARTIFACT", "")
        if not finding_path:
            safe_run_id = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip(".-") or "worker"
            finding_path = os.path.join(
                "/shared-tmpfs",
                "fuzzer-findings",
                f"{safe_run_id}.json",
            )
        try:
            write_finding_artifact(
                finding_path,
                run_id=run_id,
                fuzzer_id=self.fuzzer_id,
                findings=finding_records,
            )
        except (OSError, TypeError, ValueError) as exc:
            print(f"Could not save vulnerability finding artifact: {exc}")

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
        legacy_run_id = os.environ.get("HOOKPHUZZ_LEGACY_RUN_ID", "")
        return _prepare_request(
            self.config,
            base_url=candidate.http_target,
            http_method=candidate.http_method,
            fuzz_params=candidate.fuzz_params,
            fixed_params=candidate.fixed_params,
            request_id=candidate.coverage_id,
            run_id=legacy_run_id,
        )

    def _request_auth_context(self):
        return _request_auth_context_from_config(self.config)

    def _disable_auth_cookies(self):
        return _disable_auth_cookies_from_config(self.config)

    def _without_auth_cookies(self, cookies):
        return _without_auth_cookies(cookies)

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


    def ff_mutate(self, c, *, target=None):
        """Mutate one field; ``target`` = (bucket, name) pins it and leaves CmpLog hints queued."""

        while target is None and self.cmplog_hints:
            hint = self.cmplog_hints.pop(0)
            if (hint.get("opcode") == "TYPE_CHECK" and hint.get("candidate_value") is None
                    and hint.get("mutation") != "remove"):
                headers = {**c.fuzz_params['headers'], **c.fixed_params['headers']}
                content_type = headers.get('Content-Type', '').split(';', 1)[0].strip().lower()
                if c.http_method not in ['POST', 'PUT', 'PATCH', 'DELETE'] or content_type != 'application/json':
                    continue
            applied = apply_cmplog_hint(c.fuzz_params, hint)
            if applied is None:
                continue
            http_target = c.http_target
            if hint.get("mutation") == "remove" and applied["mutated_param_type"] == "query_params":
                target = urlparse.urlsplit(http_target)
                query = [(key, value) for key, value in urlparse.parse_qsl(target.query, keep_blank_values=True)
                         if key != applied["mutated_param_name"]]
                http_target = urlparse.urlunsplit(target._replace(query=urlencode(query)))
            return Candidate(
                parent=c,
                priority=self.scoring_formula.calculate_priority(c),
                http_target=http_target,
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

        if target is not None:
            param_type, param_name = target
            if param_name not in c.fuzz_params.get(param_type, {}):
                return None
        else:
            choice_keys = list(filter(lambda x: c.fuzz_params[x], c.fuzz_params))
            choice_weights = list(map(lambda x: c.fuzz_weights[x], choice_keys))
            if not choice_keys or not choice_weights:
                return None
            param_type = random.choices(choice_keys, weights=choice_weights)[0]
            param_name = random.choice(list(c.fuzz_params[param_type].keys()))

        param_value = c.fuzz_params[param_type][param_name]
        new_value = "" if param_value is None else mutator.mutate(param_value)

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
                self.vulnerability_count += 1

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
        sync_path = os.path.join(sync_dir(), "")

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

    def _ff_attempt(self, candidate, *, pause_gate, round_id, energy, attempt, target=None):
        """One mutation attempt of a round; True when the mutation found new paths."""
        if pause_gate:
            pause_gate.wait_if_paused(round_id=round_id, allocated_energy=energy, attempts_used=attempt)
        interesting = False
        if self.stop_on_vuln_count > 0 and os.path.exists("/sync-tmpfs/vuln_found"):
            sys.exit(1337)

        mutated_candidate = (self.ff_mutate(candidate) if target is None
                             else self.ff_mutate(candidate, target=target))
        if not mutated_candidate:
            return False
        mutated_candidate_hash = mutated_candidate.get_params_hash()

        #print("Mutation: ", mutated_candidate_hash, mutated_candidate.fuzz_params)
        if mutated_candidate_hash in self.seen_mutations:
            return False
        else:
            self.seen_mutations.add(mutated_candidate_hash)

        if os.path.exists(mutated_candidate.get_sync_file()):
            mutated_candidate = self.ff_load_candidate(mutated_candidate_hash)
            if mutated_candidate.is_interesting and mutated_candidate_hash not in self.ff_interesting_candidates_hashes:
                self.ff_interesting_candidates.append(mutated_candidate)
                self.ff_interesting_candidates_hashes.add(mutated_candidate_hash)
            return False

        if pause_gate:
            # A request that arrived while this mutation was generated.
            pause_gate.wait_if_paused(round_id=round_id, allocated_energy=energy, attempts_used=attempt)
        self.ff_send_request(mutated_candidate)
        self._ingest_cmplog_hints(mutated_candidate)

        measured = self.ff_get_coverage(mutated_candidate) != 0
        self.calculate_score(mutated_candidate)
        self.calculate_priority(mutated_candidate)
        self._remember_scored(mutated_candidate, pause_gate, measured=measured)


        if self.ff_has_exceptions(mutated_candidate):
            pass

        if self.ff_has_vulns(mutated_candidate):
            self.ff_vulnerable_candidates.append(mutated_candidate)

            for vuln_type in mutated_candidate.vulns:
                stop = int(time.time())
                diff = stop - self.start_time
                print(f"\n\n\n\n\n\nFound {vuln_type}! in {diff}s\n\n\n\n\n\n")
            if self.stop_on_vuln_count > 0 and self.vulnerability_count >= self.stop_on_vuln_count:
                stop = int(time.time())
                diff = stop - self.start_time
                with open("/sync-tmpfs/vuln_found", "w") as f:
                    f.write(f"Found by {self.fuzzer_id} in {diff}s")
                sys.exit(1337)

        if self.ff_is_interesting(mutated_candidate):
            #print("TP priority / score:", mutated_candidate.priority, mutated_candidate.score)
            self.ff_interesting_candidates.append(mutated_candidate)
            self.ff_interesting_candidates_hashes.add(mutated_candidate_hash)
            if (mutated_candidate.mutated_param_type and mutated_candidate.mutated_param_name
                    and mutated_candidate.mutated_param_name in mutated_candidate.fuzz_params.get(
                        mutated_candidate.mutated_param_type, {})):
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
            interesting = True

        mutated_candidate.write_sync_file()
        if os.environ["FUZZER_CLEANUP"] == "1":
            self.cleanup(mutated_candidate)
        return interesting

    def _remember_scored(self, candidate, pause_gate, *, measured):
        """Online-linked only: original PHUZZ energy of recent sent requests, by request ID (= coverage ID).

        Numbers only, so no response body or parent chain stays alive. A request without
        coverage has no measured energy (ff_get_coverage returned 0), so it is not cached.
        """
        if pause_gate is None or not measured:
            return
        self._scored_energy[candidate.coverage_id] = int(phuzz_base_energy(candidate, candidate.score))
        while len(self._scored_energy) > 4096:
            self._scored_energy.popitem(last=False)

    def _phuzz_energy_for(self, request_id):
        return self._scored_energy.get(request_id)

    def _reject_priority_seed(self, reason, detail=""):
        """A handoff promised the verified seed first: stop instead of fuzzing without it."""
        self._priority_log({"status": "REJECTED", "reason": reason, "detail": detail})
        sys.exit(f"HOOKPHUZZ_PRIORITY_SEED rejected: {reason}")

    def _choose_priority_target(self, targets):
        return random.choice(targets)

    def _priority_log(self, payload):
        print("[priority] " + json.dumps(payload, sort_keys=True))
        # Host copy for later checks and scripts/wordpress/watch-online-linked.ps1: stdout dies with the
        # container and fuzzer-N is wiped on start, so keep one file per worker run beside those folders.
        run_id = os.environ.get("HOOKPHUZZ_LEGACY_RUN_ID", "")
        name = re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id).strip("-") or f"fuzzer-{self.fuzzer_id}"
        path = os.path.join(os.path.dirname(self.output_dir), "priority", name + ".json")
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path + ".tmp", "w", encoding="utf-8") as handle:
                json.dump({**payload, "worker_run_id": run_id}, handle, sort_keys=True)
            os.replace(path + ".tmp", path)
        except OSError as exc:
            print(f"[priority] could not save {path}: {exc}")

    def _load_priority_seed(self):
        """Build the verified replay seed of HOOKPHUZZ_PRIORITY_SEED, or None after logging why not."""
        raw = os.environ.get("HOOKPHUZZ_PRIORITY_SEED", "")
        if not raw:
            return None
        try:
            descriptor = json.loads(raw)
            slug = str(descriptor["replay_slug"])
            if not slug or os.path.isabs(slug) or ".." in slug.replace("\\", "/").split("/"):
                raise ValueError("replay_slug must stay under the config root")
            mode = handoff.priority_energy_mode(descriptor.get("mode"))
            for name in ("allocated_energy", "attempts_used", "seed_phuzz_energy"):
                if name in descriptor and type(descriptor[name]) is not int:
                    raise ValueError(f"{name} must be an integer")
            with open(os.path.join(PRIORITY_CONFIG_DIR, slug + ".json"), encoding="utf-8-sig") as f:
                replay = json.load(f)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            self._reject_priority_seed("PRIORITY_SEED_UNREADABLE", str(exc))
        if handoff.config_hash(replay) != descriptor.get("replay_hash"):
            self._reject_priority_seed("REPLAY_HASH_MISMATCH")
        buckets = ["headers", "cookies", "query_params", "body_params"]
        targets = []
        for row in descriptor.get("targets") or []:
            if (isinstance(row, list) and len(row) == 2 and row[0] in buckets
                    and row[1] in getattr(self, f"fuzz_{row[0]}", {})):
                targets.append((row[0], row[1]))
        if not targets:
            self._reject_priority_seed("NO_FUZZABLE_TARGET")
        fixed_params, fuzz_params = {}, {}
        for bucket in buckets:
            section = replay.get(bucket) if isinstance(replay.get(bucket), dict) else {}
            values = {row["name"]: row["value"] for row in section.get("data", [])
                      if isinstance(row, dict) and "name" in row and "value" in row}
            # The updated config decides fixed/fuzz; the replay supplies the branch-opening values.
            fixed_params[bucket] = {name: values.get(name, seeds[0] if seeds else "")
                                    for name, seeds in getattr(self, f"fixed_{bucket}").items()}
            fuzz_params[bucket] = {name: values.get(name, seeds[0] if seeds else "")
                                   for name, seeds in getattr(self, f"fuzz_{bucket}").items()}
        seed = Candidate(
            score=100, priority=100, http_target=self.config["target"],
            http_method=(replay.get("methods") or self.http_methods)[0], is_initial_candidate=True,
            fixed_params=fixed_params, fuzz_params=fuzz_params,
            fuzz_weights={bucket: getattr(self, f"weight_{bucket}") for bucket in buckets},
            fuzzer_id=self.fuzzer_id,
        )
        self.ff_reset_cookies(seed)
        return {"candidate": seed, "targets": targets, "descriptor": {**descriptor, "mode": mode}}

    def _ff_priority_round(self, priority, pause_gate):
        """Send the verified seed, then mutate only its new fields before any normal seed."""
        seed, targets, descriptor = priority["candidate"], priority["targets"], priority["descriptor"]
        if pause_gate:
            pause_gate.wait_if_paused(round_id=0, allocated_energy=0, attempts_used=0)
        self.ff_send_request(seed)
        self._ingest_cmplog_hints(seed)
        coverage_missing = self.ff_get_coverage(seed) == 0
        self.calculate_score(seed)
        self.calculate_priority(seed)
        if self.ff_is_interesting(seed):
            self.ff_interesting_candidates.append(seed)
            self.ff_interesting_candidates_hashes.add(seed.get_params_hash())
        self.ff_candidates.append(seed)
        self.seen_mutations.add(seed.get_params_hash())
        self._remember_scored(seed, pause_gate, measured=not coverage_missing)
        # The old worker's PHUZZ energy of the verified request itself; else score the rebuilt seed.
        if type(descriptor.get("seed_phuzz_energy")) is int and descriptor["seed_phuzz_energy"] > 0:
            seed_energy, seed_source = descriptor["seed_phuzz_energy"], "WORKER_SCORE"
        elif coverage_missing:
            seed_energy, seed_source = 1, "SEED_COVERAGE_UNAVAILABLE"
        else:
            # seed-plus-bonus is defined on original PHUZZ, not on the scheduler's scoring mode.
            seed_energy, seed_source = int(phuzz_base_energy(seed, seed.score)), "RESCORED"
        allocated = int(descriptor.get("allocated_energy") or 0)
        used = int(descriptor.get("attempts_used") or 0)
        energy = handoff.priority_energy(descriptor["mode"], seed_energy=seed_energy, target_count=len(targets),
                                         allocated_energy=allocated, attempts_used=used)
        per_field = Counter()
        for attempt in range(energy):
            target = self._choose_priority_target(targets)
            per_field[f"{target[0]}:{target[1]}"] += 1
            self._ff_attempt(seed, pause_gate=pause_gate, round_id=0, energy=energy, attempt=attempt, target=target)
        self._priority_log({
            "status": "DONE", "mode": descriptor["mode"], "allocated_energy": allocated, "attempts_used": used,
            "seed_energy": seed_energy, "seed_energy_source": seed_source,
            "bonus": len(targets) if descriptor["mode"] == "seed-plus-bonus" else 0,
            "granted": energy, "attempted": sum(per_field.values()), "per_field": dict(per_field),
            "seed_coverage": "SEED_COVERAGE_UNAVAILABLE" if coverage_missing else "AVAILABLE",
        })

    def fuzz_fast(self):
        self.ff_candidates = []
        # Th is self.seen_mutations
        self.ff_interesting_candidates = []
        self.ff_interesting_candidates_hashes = set()
        self.ff_vulnerable_candidates = []
        self._scored_energy = OrderedDict()
        # Online-linked handoff: stop between requests while the coordinator verifies a child.
        pause_gate = PauseGate.from_env(energy_for=self._phuzz_energy_for)

        # A config activated by a verified handoff fuzzes its new fields first.
        priority = self._load_priority_seed()
        if priority is not None:
            self._ff_priority_round(priority, pause_gate)

        # Send initial requests first
        for c in self.generate_initial_candidates():
            if pause_gate:
                pause_gate.wait_if_paused(round_id=0, allocated_energy=0, attempts_used=0)
            self.ff_send_request(c)
            self._ingest_cmplog_hints(c)
            measured = self.ff_get_coverage(c) != 0
            self.calculate_score(c)
            self.calculate_priority(c)
            self._remember_scored(c, pause_gate, measured=measured)
            if self.ff_is_interesting(c):
                self.ff_interesting_candidates.append(c)
                self.ff_interesting_candidates_hashes.add(c.get_params_hash())
            self.ff_candidates.append(c)
            self.seen_mutations.add(c.get_params_hash())

        sync_total, sync_new, sync_interesting = self.ff_sync_candidates()
        print("Synced new candidates (total / new / interesting): ", sync_total, sync_new, sync_interesting)

        choose_offset = 0
        round_id = 0
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
            round_id += 1
            # This loop is where integer `energy` becomes actual mutation attempts.
            for i in range(energy):
                if self._ff_attempt(candidate, pause_gate=pause_gate, round_id=round_id, energy=energy, attempt=i):
                    choose_offset = 0


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
