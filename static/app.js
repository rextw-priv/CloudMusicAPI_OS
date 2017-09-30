document.body.classList.remove('nojs');
document.body.classList.add('js');
$(function() {
    function hasTouch() {
        return (('ontouchstart' in window) || // html5 browsers
            (navigator.maxTouchPoints > 0) || // future IE
            (navigator.msMaxTouchPoints > 0)); // current IE10
    }

    var $body = $('body');
    var base = location.protocol + '//' + location.host + '/';
    var errors = ['', '音樂解析失敗'];
    var preview = document.getElementById('preview');

    var app = new Vue({
        el: '#app',
        data: {
            verified: $body.data('verified'),
            error: '',

            src_url: '',
            rate: 128000,

            url: '',
            song: {}
        },
        methods: {
            sign: function(e) {
                e.preventDefault();
                app.url = '';
                var data = $('#sign', app.$el).serialize();
                var songId = app.src_url;
                if (!/^\d+$/.test(songId)) {
                    // xxx/song/12345
                    // xxx/song?id=12345
                    var m = songId.match(/song(?:\?id=|\/)(\d+)/);
                    if (m && m.length > 0) {
                        songId = m[1];
                    } else {
                        app.error = "無效的 ID 或無法識別的網址。";
                        return;
                    }
                }

                var param = songId + '/' + app.rate;

                $.post('/sign/' + param, data, function(response) {
                    app.verified = response.verified;
                    if (!response.verified) {
                        app.error = '請先填寫驗證碼!';
                        loadCaptcha();
                        return;
                    }

                    if (response.errno) {
                        app.error = errors[response.errno];
                        return;
                    }

                    app.url = base + param + '/' + response.sign;
                    app.song = response.song;
                    app.error = '';
                }).fail(function() {
                    app.error = "伺服器內部錯誤。";
                });
            },

            sel: function(e) {
                var target = e.currentTarget;
                target.setSelectionRange(0, target.value.length);
            }
        },
        created: function() {
            document.body.classList.add('vue');
            if (!this.verified) {
                loadCaptcha();
            }
        }
    });

    var captchaId = null;

    function loadCaptcha() {
        if (window.grecaptcha) {
            if (captchaId !== null) {
                grecaptcha.reset(captchaId);
            } else {
                captchaId = grecaptcha.render('recaptcha', {
                    'sitekey': $body.data('sitekey')
                });
            }
        } else {
            var script = document.createElement('script');
            script.src = 'https://www.google.com/recaptcha/api.js?onload=loadCaptcha&render=explicit';
            document.body.appendChild(script);
        }
    }

    window.loadCaptcha = loadCaptcha;
    var copyBtn = document.getElementById('copy');
    var clipboard = new Clipboard(copyBtn);
    copyBtn.addEventListener('click', function(e) {
        e.preventDefault();
    });
    clipboard.on('success', function() {
        alert('複製成功!');
    }).on('error', function() {
        var action = hasTouch() ? '長按' : '右鍵';
        alert('複製失敗，請' + action + '網址然後選擇複製！');
    });


    // window.app = app;
});