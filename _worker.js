import { connect } from "cloudflare:sockets";
let config_JSON, 反代IP = '', 启用SOCKS5反代 = null, 启用SOCKS5全局反代 = false, 我的SOCKS5账号 = '', parsedSocks5Address = {};
let SOCKS5白名单 = ['*tapecontent.net', '*cloudatacdn.com', '*loadshare.org', '*cdn-centaurus.com', 'scholar.google.com'];
const Pages静态页面 = 'https://edt-pages.github.io';
///////////////////////////////////////////////////////主程序入口///////////////////////////////////////////////
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const UA = request.headers.get('User-Agent') || 'null';
        const upgradeHeader = request.headers.get('Upgrade');
        const 管理员密码 = env.ADMIN || env.admin || env.PASSWORD || env.password || env.pswd || env.TOKEN || env.KEY || env.UUID || env.uuid;
        const 加密秘钥 = env.KEY || '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改';
        const userIDMD5 = await MD5MD5(管理员密码 + 加密秘钥);
        const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
        const envUUID = env.UUID || env.uuid;
        const userID = (envUUID && uuidRegex.test(envUUID)) ? envUUID.toLowerCase() : [userIDMD5.slice(0, 8), userIDMD5.slice(8, 12), '4' + userIDMD5.slice(13, 16), '8' + userIDMD5.slice(17, 20), userIDMD5.slice(20)].join('-');
        const hosts = env.HOST ? (await 整理成数组(env.HOST)).map(h => h.toLowerCase().replace(/^https?:\/\//, '').split('/')[0].split(':')[0]) : [url.hostname];
        const host = hosts[0];
        if (env.PROXYIP) {
            const proxyIPs = await 整理成数组(env.PROXYIP);
            反代IP = proxyIPs[Math.floor(Math.random() * proxyIPs.length)];
        } else 反代IP = (request.cf.colo + '.PrOxYIp.CmLiUsSsS.nEt').toLowerCase();
        const 访问IP = request.headers.get('X-Real-IP') || request.headers.get('CF-Connecting-IP') || request.headers.get('X-Forwarded-For') || request.headers.get('True-Client-IP') || request.headers.get('Fly-Client-IP') || request.headers.get('X-Appengine-Remote-Addr') || request.headers.get('X-Forwarded-For') || request.headers.get('X-Real-IP') || request.headers.get('X-Cluster-Client-IP') || request.cf?.clientTcpRtt || '未知IP';
        if (env.GO2SOCKS5) SOCKS5白名单 = await 整理成数组(env.GO2SOCKS5);
        if (!upgradeHeader || upgradeHeader !== 'websocket') {
            if (url.protocol === 'http:') return Response.redirect(url.href.replace(`http://${url.hostname}`, `https://${url.hostname}`), 301);
            if (!管理员密码) return fetch(Pages静态页面 + '/noADMIN').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            if (!env.KV) return fetch(Pages静态页面 + '/noKV').then(r => { const headers = new Headers(r.headers); headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate'); headers.set('Pragma', 'no-cache'); headers.set('Expires', '0'); return new Response(r.body, { status: 404, statusText: r.statusText, headers }); });
            const 访问路径 = url.pathname.slice(1).toLowerCase();
            const 区分大小写访问路径 = url.pathname.slice(1);
            if (访问路径 === 加密秘钥 && 加密秘钥 !== '勿动此默认密钥，有需求请自行通过添加变量KEY进行修改') {//快速订阅
                const params = new URLSearchParams(url.search);
                params.set('token', await MD5MD5(host + userID));
                return new Response('重定向中...', { status: 302, headers: { 'Location': `/sub?${params.toString()}` } });
            } else if (访问路径 === 'login') {//处理登录页面和登录请求
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                if (authCookie == await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/admin' } });
                if (request.method === 'POST') {
                    const formData = await request.text();
                    const params = new URLSearchParams(formData);
                    const 输入密码 = params.get('password');
                    if (输入密码 === 管理员密码) {
                        // 密码正确，设置cookie并返回成功标记
                        const 响应 = new Response(JSON.stringify({ success: true }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        响应.headers.set('Set-Cookie', `auth=${await MD5MD5(UA + 加密秘钥 + 管理员密码)}; Path=/; Max-Age=86400; HttpOnly`);
                        return 响应;
                    }
                }
                return fetch(Pages静态页面 + '/login');
            } else if (访问路径 === 'admin' || 访问路径.startsWith('admin/')) {//验证cookie后响应管理页面
                const cookies = request.headers.get('Cookie') || '';
                const authCookie = cookies.split(';').find(c => c.trim().startsWith('auth='))?.split('=')[1];
                // 没有cookie或cookie错误，跳转到/login页面
                if (!authCookie || authCookie !== await MD5MD5(UA + 加密秘钥 + 管理员密码)) return new Response('重定向中...', { status: 302, headers: { 'Location': '/login' } });
                if (访问路径 === 'admin/log.json') {// 读取日志内容
                    const 读取日志内容 = await env.KV.get('log.json') || '[]';
                    return new Response(读取日志内容, { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (区分大小写访问路径 === 'admin/getCloudflareUsage') {// 查询请求量
                    try {
                        const Usage_JSON = await getCloudflareUsage(url.searchParams.get('Email'), url.searchParams.get('GlobalAPIKey'), url.searchParams.get('AccountID'), url.searchParams.get('APIToken'));
                        return new Response(JSON.stringify(Usage_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json' } });
                    } catch (err) {
                        const errorResponse = { msg: '查询请求量失败，失败原因：' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (区分大小写访问路径 === 'admin/getADDAPI') {// 验证优选API
                    if (url.searchParams.get('url')) {
                        const 待验证优选URL = url.searchParams.get('url');
                        try {
                            new URL(待验证优选URL);
                            const 优选API的IP = await 请求优选API([待验证优选URL], url.searchParams.get('port') || '443');
                            return new Response(JSON.stringify({ success: true, data: 优选API的IP }, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (err) {
                            const errorResponse = { msg: '验证优选API失败，失败原因：' + err.message, error: err.message };
                            return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        }
                    }
                    return new Response(JSON.stringify({ success: false, data: [] }, null, 2), { status: 403, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                } else if (访问路径 === 'admin/check') {// SOCKS5代理检查
                    let 检测代理响应;
                    if (url.searchParams.has('socks5')) {
                        检测代理响应 = await SOCKS5可用性验证('socks5', url.searchParams.get('socks5'));
                    } else if (url.searchParams.has('http')) {
                        检测代理响应 = await SOCKS5可用性验证('http', url.searchParams.get('http'));
                    } else {
                        return new Response(JSON.stringify({ error: '缺少代理参数' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                    return new Response(JSON.stringify(检测代理响应, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                }

                config_JSON = await 读取config_JSON(env, host, userID, env.PATH);

                if (访问路径 === 'admin/init') {// 重置配置为默认值
                    try {
                        config_JSON = await 读取config_JSON(env, host, userID, env.PATH, true);
                        ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Init_Config', config_JSON));
                        config_JSON.init = '配置已重置为默认值';
                        return new Response(JSON.stringify(config_JSON, null, 2), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    } catch (err) {
                        const errorResponse = { msg: '配置重置失败，失败原因：' + err.message, error: err.message };
                        return new Response(JSON.stringify(errorResponse, null, 2), { status: 500, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                    }
                } else if (request.method === 'POST') {// 处理 KV 操作（POST 请求）
                    if (访问路径 === 'admin/config.json') { // 保存config.json配置
                        try {
                            const newConfig = await request.json();
                            // 验证配置完整性
                            if (!newConfig.UUID || !newConfig.HOST) return new Response(JSON.stringify({ error: '配置不完整' }), { status: 400, headers: { 'Content-Type': 'application/json;charset=utf-8' } });

                            // 保存到 KV
                            await env.KV.put('config.json', JSON.stringify(newConfig, null, 2));
                            ctx.waitUntil(请求日志记录(env, request, 访问IP, 'Save_Config', config_JSON));
                            return new Response(JSON.stringify({ success: true, message: '配置已保存' }), { status: 200, headers: { 'Content-Type': 'application/json;charset=utf-8' } });
                        } catch (error) {
   
