# Show All Comments In One Page

Plugin file tham chieu:
- `bt-comments.php`

Muc tieu note:
- Theo doi callback dang ky/thuc thi khi fuzz plugin nay.

Callback plugin de UOPZ co the tinh:
- `admin_menu` -> `bt_comments_create_menu`
- `wp_ajax_sac_post_type_call` -> `sac_post_type_call_callback`
- `wp_ajax_nopriv_sac_post_type_call` -> `sac_post_type_call_callback`
- `wp_enqueue_scripts` -> `sac_wp_enqueue_styles_and_scripts`

Callback co dieu kien:
- `admin_init` -> `register_bt_comments_settings`
  - Chi co khi da vao nhanh admin menu.
- `comments_clauses` -> `wpse_121051`
  - Chi co khi shortcode `[bt_comments]` duoc render.

Callback core nen bo qua khi tinh plugin coverage:
- `pre_option_page_comments` -> `__return_true`
  - Day la callback cua WordPress core, plugin chi muon gia tri `true`.

Cach trigger nhanh:
- AJAX:
  - `POST /wp-admin/admin-ajax.php?action=sac_post_type_call`
- Admin:
  - `GET /wp-admin/admin.php?page=bt-comments`
- Shortcode:
  - Tao 1 page co `[bt_comments]`, sau do request page do.

Ghi chu cho fuzz:
- Thuc te thuong thay `4` registered callbacks truoc.
- Muon thay them callback co dieu kien thi phai di dung entry point.
- `apply_filters("the_content", ...)` khong tu tao `registered_callbacks`; no chi fire hook da co.
