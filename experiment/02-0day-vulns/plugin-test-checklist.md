# Checklist test plugin experiment

Cập nhật từ corpus experiment/02-0day-vulns ngày 22 09 2026.

Hiện có 183 plugin ZIP. Mốc artifact hiện tại gồm 111 plugin có ít nhất một config JSON và 72 plugin chưa có config JSON. Tất cả ô Đã test được để trống; chỉ tick khi có bằng chứng runtime hoặc log test cụ thể.

## Cách cập nhật

- Cột Đã test: tick [x] sau khi đã chạy test và lưu được artifact hoặc log tương ứng.
- Cột Có lỗi: để [ ] khi chưa kiểm tra. Khi có lỗi, đổi thành [x] và ghi lỗi ngắn gọn ở cột cuối.
- Nếu đã chạy nhưng không lỗi, ghi Không lỗi ở cột cuối; không suy luận từ HTTP 200, registration, hoặc việc có config.
- Ghi đường dẫn run, summary, log, hoặc config vào cột Chi tiết lỗi hoặc evidence để agent khác có thể kiểm tra lại.

## Tóm tắt

| Nhóm | Số lượng |
| --- | ---: |
| Có config JSON hiện tại | 111 |
| Có ZIP nhưng chưa có config JSON | 72 |
| Tổng cộng | 183 |

## Danh sách plugin

| STT | Plugin ZIP | Đã test | Có lỗi? | Config JSON | Chi tiết lỗi hoặc evidence |
| ---: | --- | :---: | :---: | ---: | --- |
| 1 | 300000-ad-inserter.2.7.28.zip | [ ] | [ ] | 3 | |
| 2 | 300000-astra-widgets.1.2.12.zip | [ ] | [ ] | 1 | |
| 3 | 300000-child-theme-configurator.2.6.2.zip | [ ] | [ ] | 0 | |
| 4 | 300000-cmb2.zip | [ ] | [ ] | 2 | |
| 5 | 300000-custom-fonts.1.3.7.zip | [ ] | [ ] | 1 | |
| 6 | 300000-easy-fancybox.1.9.5.zip | [ ] | [ ] | 0 | |
| 7 | 300000-fluentform.4.3.25.zip | [ ] | [ ] | 0 | |
| 8 | 300000-formidable.6.3.zip | [ ] | [ ] | 0 | |
| 9 | 300000-gutenberg.15.7.0.zip | [ ] | [ ] | 0 | |
| 10 | 300000-happy-elementor-addons.zip | [ ] | [ ] | 13 | |
| 11 | 300000-health-check.1.6.0.zip | [ ] | [ ] | 2 | |
| 12 | 300000-imsanity.2.8.2.zip | [ ] | [ ] | 4 | |
| 13 | 300000-iwp-client.zip | [ ] | [ ] | 0 | |
| 14 | 300000-kadence-blocks.3.0.37.zip | [ ] | [ ] | 16 | |
| 15 | 300000-leadin.10.1.16.zip | [ ] | [ ] | 0 | |
| 16 | 300000-malcare-security.4.97.zip | [ ] | [ ] | 0 | |
| 17 | 300000-newsletter.7.7.0.zip | [ ] | [ ] | 6 | |
| 18 | 300000-nextend-facebook-connect.3.1.8.zip | [ ] | [ ] | 0 | |
| 19 | 300000-otter-blocks.zip | [ ] | [ ] | 2 | |
| 20 | 300000-password-protected.2.6.2.zip | [ ] | [ ] | 0 | |
| 21 | 300000-pdf-embedder.4.6.4.zip | [ ] | [ ] | 3 | |
| 22 | 300000-popup-builder.4.1.14.zip | [ ] | [ ] | 24 | |
| 23 | 300000-post-smtp.2.4.9.zip | [ ] | [ ] | 3 | |
| 24 | 300000-pretty-link.3.4.2.zip | [ ] | [ ] | 16 | |
| 25 | 300000-shortpixel-image-optimiser.5.2.1.zip | [ ] | [ ] | 6 | |
| 26 | 300000-stops-core-theme-and-plugin-updates.9.0.15.zip | [ ] | [ ] | 3 | |
| 27 | 300000-table-of-contents-plus.2302.zip | [ ] | [ ] | 0 | |
| 28 | 300000-themeisle-companion.zip | [ ] | [ ] | 1 | |
| 29 | 300000-velvet-blues-update-urls.3.2.10.zip | [ ] | [ ] | 0 | |
| 30 | 300000-webp-converter-for-media.5.8.6.zip | [ ] | [ ] | 0 | |
| 31 | 300000-widget-importer-exporter.1.6.zip | [ ] | [ ] | 0 | |
| 32 | 300000-woocommerce-gateway-paypal-express-checkout.2.1.3.zip | [ ] | [ ] | 1 | |
| 33 | 300000-woocommerce-pdf-invoices-packing-slips.3.5.2.zip | [ ] | [ ] | 9 | |
| 34 | 300000-woo-variation-swatches.2.0.20.zip | [ ] | [ ] | 0 | |
| 35 | 300000-wpcf7-recaptcha.1.4.3.zip | [ ] | [ ] | 0 | |
| 36 | 300000-wpcf7-redirect.2.8.0.zip | [ ] | [ ] | 9 | |
| 37 | 300000-wp-migrate-db.2.6.5.zip | [ ] | [ ] | 1 | |
| 38 | 300000-wp-sitemap-page.zip | [ ] | [ ] | 0 | |
| 39 | 300000-wp-user-avatar.4.10.1.zip | [ ] | [ ] | 34 | |
| 40 | 300000-wpvivid-backuprestore.0.9.86.zip | [ ] | [ ] | 109 | |
| 41 | 400000-add-to-any.1.8.6.zip | [ ] | [ ] | 0 | |
| 42 | 400000-admin-menu-editor.1.11.zip | [ ] | [ ] | 1 | |
| 43 | 400000-amp.2.4.1.zip | [ ] | [ ] | 0 | |
| 44 | 400000-black-studio-tinymce-widget.2.7.2.zip | [ ] | [ ] | 0 | |
| 45 | 400000-click-to-chat-for-whatsapp.3.27.2.zip | [ ] | [ ] | 0 | |
| 46 | 400000-contact-form-7-honeypot.zip | [ ] | [ ] | 0 | |
| 47 | 400000-easy-table-of-contents.2.0.47.1.zip | [ ] | [ ] | 4 | |
| 48 | 400000-font-awesome.4.3.2.zip | [ ] | [ ] | 0 | |
| 49 | 400000-force-regenerate-thumbnails.2.1.2.zip | [ ] | [ ] | 1 | |
| 50 | 400000-forminator.1.23.3.zip | [ ] | [ ] | 18 | |
| 51 | 400000-gtranslate.3.0.3.zip | [ ] | [ ] | 0 | |
| 52 | 400000-header-footer.3.2.5.zip | [ ] | [ ] | 0 | |
| 53 | 400000-header-footer-code-manager.1.1.32.zip | [ ] | [ ] | 0 | |
| 54 | 400000-intuitive-custom-post-order.3.1.4.1.zip | [ ] | [ ] | 3 | |
| 55 | 400000-megamenu.3.2.2.zip | [ ] | [ ] | 13 | |
| 56 | 400000-pixelyoursite.9.3.6.zip | [ ] | [ ] | 4 | |
| 57 | 400000-woo-checkout-field-editor-pro.zip | [ ] | [ ] | 2 | |
| 58 | 400000-wp-google-maps.zip | [ ] | [ ] | 4 | |
| 59 | 400000-wp-reset.1.97.zip | [ ] | [ ] | 2 | |
| 60 | 500000-coblocks.3.0.3.zip | [ ] | [ ] | 1 | |
| 61 | 500000-contact-form-cfdb7.zip | [ ] | [ ] | 0 | |
| 62 | 500000-custom-css-js.3.43.zip | [ ] | [ ] | 0 | |
| 63 | 500000-mailchimp-for-woocommerce.2.8.3.zip | [ ] | [ ] | 13 | |
| 64 | 500000-official-facebook-pixel.3.0.10.zip | [ ] | [ ] | 3 | |
| 65 | 500000-really-simple-captcha.zip | [ ] | [ ] | 0 | |
| 66 | 500000-siteguard.1.7.5.zip | [ ] | [ ] | 0 | |
| 67 | 500000-taxonomy-terms-order.1.7.5.zip | [ ] | [ ] | 1 | |
| 68 | 500000-ultimate-addons-for-gutenberg.2.5.1.zip | [ ] | [ ] | 23 | |
| 69 | 600000-complianz-gdpr.6.4.3.zip | [ ] | [ ] | 23 | |
| 70 | 600000-creame-whatsapp-me.4.5.20.zip | [ ] | [ ] | 0 | |
| 71 | 600000-duracelltomi-google-tag-manager.1.16.2.zip | [ ] | [ ] | 1 | |
| 72 | 600000-easy-wp-smtp.2.1.0.zip | [ ] | [ ] | 12 | |
| 73 | 600000-enable-media-replace.4.1.2.zip | [ ] | [ ] | 2 | |
| 74 | 600000-ga-google-analytics.20230306.zip | [ ] | [ ] | 0 | |
| 75 | 600000-google-listings-and-ads.2.4.4.zip | [ ] | [ ] | 1 | |
| 76 | 600000-kirki.zip | [ ] | [ ] | 3 | |
| 77 | 600000-limit-login-attempts.1.7.2.zip | [ ] | [ ] | 0 | |
| 78 | 600000-mailpoet.4.14.0.zip | [ ] | [ ] | 0 | |
| 79 | 600000-mainwp-child.4.4.1.zip | [ ] | [ ] | 3 | |
| 80 | 600000-nextgen-gallery.3.35.zip | [ ] | [ ] | 4 | |
| 81 | 600000-post-types-order.2.0.5.zip | [ ] | [ ] | 2 | |
| 82 | 600000-premium-addons-for-elementor.4.9.55.zip | [ ] | [ ] | 29 | |
| 83 | 600000-under-construction-page.3.97.zip | [ ] | [ ] | 3 | |
| 84 | 600000-woocommerce-payments.5.8.1.zip | [ ] | [ ] | 14 | |
| 85 | 600000-woocommerce-paypal-payments.2.0.4.zip | [ ] | [ ] | 0 | |
| 86 | 600000-wp-pagenavi.2.94.1.zip | [ ] | [ ] | 0 | |
| 87 | 600000-wp-statistics.14.1.zip | [ ] | [ ] | 0 | |
| 88 | 700000-backwpup.4.0.0.zip | [ ] | [ ] | 3 | |
| 89 | 700000-broken-link-checker.2.0.0.zip | [ ] | [ ] | 6 | |
| 90 | 700000-creative-mail-by-constant-contact.1.6.7.zip | [ ] | [ ] | 2 | |
| 91 | 700000-disable-gutenberg.2.9.zip | [ ] | [ ] | 0 | |
| 92 | 700000-flamingo.2.3.zip | [ ] | [ ] | 0 | |
| 93 | 700000-google-analytics-dashboard-for-wp.7.15.2.zip | [ ] | [ ] | 44 | |
| 94 | 700000-imagify.2.1.1.zip | [ ] | [ ] | 4 | |
| 95 | 700000-meta-box.5.6.18.zip | [ ] | [ ] | 0 | |
| 96 | 700000-ml-slider.3.30.1.zip | [ ] | [ ] | 8 | |
| 97 | 700000-ocean-extra.2.1.6.zip | [ ] | [ ] | 25 | |
| 98 | 700000-polylang.3.3.3.zip | [ ] | [ ] | 8 | |
| 99 | 700000-popup-maker.1.18.1.zip | [ ] | [ ] | 7 | |
| 100 | 700000-shortcodes-ultimate.5.12.11.zip | [ ] | [ ] | 7 | |
| 101 | 700000-so-widgets-bundle.1.49.2.zip | [ ] | [ ] | 15 | |
| 102 | 700000-user-role-editor.4.63.3.zip | [ ] | [ ] | 0 | |
| 103 | 800000-antispam-bee.2.11.3.zip | [ ] | [ ] | 0 | |
| 104 | 800000-code-snippets.3.3.0.zip | [ ] | [ ] | 1 | |
| 105 | 800000-facebook-for-woocommerce.3.0.22.zip | [ ] | [ ] | 7 | |
| 106 | 800000-hello-dolly.1.7.2.zip | [ ] | [ ] | 0 | |
| 107 | 800000-maintenance.4.07.zip | [ ] | [ ] | 2 | |
| 108 | 800000-safe-svg.2.1.1.zip | [ ] | [ ] | 0 | |
| 109 | 800000-sg-security.1.4.5.zip | [ ] | [ ] | 2 | |
| 110 | 800000-siteorigin-panels.2.22.1.zip | [ ] | [ ] | 12 | |
| 111 | 800000-sucuri-scanner.1.8.39.zip | [ ] | [ ] | 0 | |
| 112 | 800000-tablepress.2.1.2.zip | [ ] | [ ] | 1 | |
| 113 | 800000-the-events-calendar.6.0.12.zip | [ ] | [ ] | 6 | |
| 114 | 800000-wp-maintenance-mode.2.6.7.zip | [ ] | [ ] | 16 | |
| 115 | 800000-yith-woocommerce-wishlist.3.20.0.zip | [ ] | [ ] | 4 | |
| 116 | 900000-breadcrumb-navxt.7.2.0.zip | [ ] | [ ] | 1 | |
| 117 | 900000-envato-elements.2.0.12.zip | [ ] | [ ] | 1 | |
| 118 | 900000-ninja-forms.3.6.23.zip | [ ] | [ ] | 18 | |
| 119 | 900000-smart-slider-3.3.5.1.14.zip | [ ] | [ ] | 0 | |
| 120 | 900000-woocommerce-gateway-stripe.7.4.0.zip | [ ] | [ ] | 0 | |
| 121 | 900000-woocommerce-services.2.2.4.zip | [ ] | [ ] | 2 | |
| 122 | 1000000-all-in-one-wp-security-and-firewall.5.1.8.zip | [ ] | [ ] | 6 | |
| 123 | 1000000-astra-sites.3.2.1.zip | [ ] | [ ] | 17 | |
| 124 | 1000000-autoptimize.3.1.7.zip | [ ] | [ ] | 7 | |
| 125 | 1000000-better-search-replace.1.4.2.zip | [ ] | [ ] | 0 | |
| 126 | 1000000-better-wp-security.8.1.6.zip | [ ] | [ ] | 4 | |
| 127 | 1000000-coming-soon.6.15.7.zip | [ ] | [ ] | 25 | |
| 128 | 1000000-cookie-law-info.3.0.9.zip | [ ] | [ ] | 5 | |
| 129 | 1000000-cookie-notice.2.4.8.zip | [ ] | [ ] | 5 | |
| 130 | 1000000-custom-post-type-ui.1.13.5.zip | [ ] | [ ] | 0 | |
| 131 | 1000000-disable-comments.2.4.3.zip | [ ] | [ ] | 3 | |
| 132 | 1000000-duplicator.1.5.3.1.zip | [ ] | [ ] | 2 | |
| 133 | 1000000-elementskit-lite.2.8.8.zip | [ ] | [ ] | 6 | |
| 134 | 1000000-essential-addons-for-elementor-lite.5.7.1.zip | [ ] | [ ] | 32 | |
| 135 | 1000000-ewww-image-optimizer.6.9.3.zip | [ ] | [ ] | 45 | |
| 136 | 1000000-google-sitemap-generator.4.1.10.zip | [ ] | [ ] | 0 | |
| 137 | 1000000-header-footer-elementor.1.6.13.zip | [ ] | [ ] | 4 | |
| 138 | 1000000-insert-headers-and-footers.2.0.11.zip | [ ] | [ ] | 7 | |
| 139 | 1000000-instagram-feed.6.1.4.zip | [ ] | [ ] | 17 | |
| 140 | 1000000-loco-translate.2.6.4.zip | [ ] | [ ] | 0 | |
| 141 | 1000000-loginizer.zip | [ ] | [ ] | 0 | |
| 142 | 1000000-one-click-demo-import.3.1.2.zip | [ ] | [ ] | 3 | |
| 143 | 1000000-optinmonster.2.13.2.zip | [ ] | [ ] | 0 | |
| 144 | 1000000-redux-framework.4.4.1.zip | [ ] | [ ] | 5 | |
| 145 | 1000000-regenerate-thumbnails.3.1.5.zip | [ ] | [ ] | 0 | |
| 146 | 1000000-seo-by-rank-math.1.0.114.zip | [ ] | [ ] | 2 | |
| 147 | 1000000-sg-cachepress.7.3.1.zip | [ ] | [ ] | 1 | |
| 148 | 1000000-svg-support.2.5.5.zip | [ ] | [ ] | 0 | |
| 149 | 1000000-w3-total-cache.2.3.1.zip | [ ] | [ ] | 0 | |
| 150 | 1000000-worker.zip | [ ] | [ ] | 0 | |
| 151 | 1000000-wp-fastest-cache.1.1.5.zip | [ ] | [ ] | 21 | |
| 152 | 1000000-wp-file-manager.zip | [ ] | [ ] | 10 | |
| 153 | 1000000-wp-multibyte-patch.2.9.zip | [ ] | [ ] | 0 | |
| 154 | 1000000-wp-optimize.3.2.14.zip | [ ] | [ ] | 2 | |
| 155 | 1000000-wps-hide-login.1.9.8.zip | [ ] | [ ] | 0 | |
| 156 | 1000000-wp-smushit.3.12.6.zip | [ ] | [ ] | 19 | |
| 157 | 2000000-advanced-custom-fields.6.1.6.zip | [ ] | [ ] | 0 | |
| 158 | 2000000-classic-widgets.0.3.zip | [ ] | [ ] | 0 | |
| 159 | 2000000-duplicate-page.zip | [ ] | [ ] | 1 | |
| 160 | 2000000-limit-login-attempts-reloaded.2.25.16.zip | [ ] | [ ] | 15 | |
| 161 | 2000000-mailchimp-for-wp.4.9.4.zip | [ ] | [ ] | 1 | |
| 162 | 2000000-redirection.5.3.10.zip | [ ] | [ ] | 0 | |
| 163 | 2000000-tinymce-advanced.5.9.0.zip | [ ] | [ ] | 0 | |
| 164 | 2000000-wp-super-cache.1.9.4.zip | [ ] | [ ] | 0 | |
| 165 | 3000000-all-in-one-seo-pack.4.3.6.1.zip | [ ] | [ ] | 2 | |
| 166 | 3000000-google-analytics-for-wordpress.8.14.1.zip | [ ] | [ ] | 35 | |
| 167 | 3000000-google-site-kit.1.99.0.zip | [ ] | [ ] | 0 | |
| 168 | 3000000-updraftplus.1.23.3.zip | [ ] | [ ] | 14 | |
| 169 | 3000000-wordpress-importer.0.8.1.zip | [ ] | [ ] | 0 | |
| 170 | 3000000-wp-mail-smtp.3.8.0.zip | [ ] | [ ] | 14 | |
| 171 | 4000000-duplicate-post.4.5.zip | [ ] | [ ] | 0 | |
| 172 | 4000000-litespeed-cache.5.4.zip | [ ] | [ ] | 0 | |
| 173 | 4000000-wordfence.7.9.2.zip | [ ] | [ ] | 0 | |
| 174 | 5000000-akismet.5.1.zip | [ ] | [ ] | 0 | |
| 175 | 5000000-all-in-one-wp-migration.7.74.zip | [ ] | [ ] | 0 | |
| 176 | 5000000-classic-editor.1.6.3.zip | [ ] | [ ] | 0 | |
| 177 | 5000000-contact-form-7.5.7.6.zip | [ ] | [ ] | 1 | |
| 178 | 5000000-elementor.3.12.2.zip | [ ] | [ ] | 2 | |
| 179 | 5000000-jetpack.12.1.zip | [ ] | [ ] | 28 | |
| 180 | 5000000-really-simple-ssl.6.2.5.zip | [ ] | [ ] | 6 | |
| 181 | 5000000-woocommerce.7.6.1.zip | [ ] | [ ] | 4 | |
| 182 | 5000000-wordpress-seo.20.6.zip | [ ] | [ ] | 8 | |
| 183 | 5000000-wpforms-lite.1.8.1.2.zip | [ ] | [ ] | 26 | |

## Dòng mẫu để thêm plugin mới

| STT | Plugin ZIP | Đã test | Có lỗi? | Config JSON | Chi tiết lỗi hoặc evidence |
| ---: | --- | :---: | :---: | ---: | --- |
| mới | plugin-name.version.zip | [ ] | [ ] | 0 | |

## Quy ước bằng chứng

Có config JSON chỉ là mốc đã tạo artifact trong experiment. Đây không tự động là runtime PASS, callback reach, convergence, Pass 2, hay bằng chứng lỗ hổng. Khi agent cập nhật, hãy giữ riêng trạng thái test, trạng thái lỗi, và đường dẫn evidence.



