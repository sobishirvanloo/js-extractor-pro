// 2 Vue route param
div.innerHTML = this.$route.query.q;
// 4 React Router hook → variable → variable
const [sp] = useSearchParams(); const term = sp.get("q"); results.innerHTML = term;
// 6 Next.js router.query → navigation
window.location.href = router.query.redirect;
// 8 Angular ActivatedRoute → navigation
window.location.href = this.route.snapshot.queryParams.next;
// 10-13 multi-hop chain
var a1 = location.hash;
var b1 = a1.slice(1);
var c1 = "<b>" + b1;
box1.innerHTML = c1;
// 15-17 kill: clean reassignment
var k1 = location.hash;
k1 = "safe";
box2.innerHTML = k1;
// 19-20 function parameter → sink, called with a source
function renderHtml(html) { panel.innerHTML = html; }
renderHtml(location.search);
// 22-23 arrow function + variable argument
const showMsg = (m) => { toast.innerHTML = m; };
const msg = decodeURIComponent(location.hash.slice(1)); showMsg(msg);
// 25-26 sanitizers
box3.innerHTML = DOMPurify.sanitize(location.hash);
var s1 = DOMPurify.sanitize(location.search); box4.innerHTML = s1;
// 28-30 URL prefixes
location.href = "/search?q=" + location.hash;
window.location = "//" + location.hash.slice(1);
location.href = location.hash.slice(1);
// 32-34 created elements
var scr = document.createElement("script"); scr.src = location.hash.slice(1);
var ifr = document.createElement("iframe"); ifr.src = document.referrer;
var lnk = document.createElement("a"); lnk.href = location.search.slice(1);
// 36-38 jQuery
$(location.hash);
$("#out").append(location.hash);
$(".btn").on("click", f);
// 40-44 weak origin check, strict origin check
window.addEventListener("message", e => { if (e.origin.indexOf("trusted.com") > -1) { eval(e.data); } });
window.addEventListener("message", function (ev) { if (ev.origin !== "https://trusted.example") return; out1.innerHTML = ev.data; });
function onMsg(evt) { out2.innerHTML = evt.data; }
window.addEventListener("message", onMsg);
window.addEventListener("message", ({ data }) => { out3.innerHTML = data; });
// 46-48 storage / cookie
bio.innerHTML = localStorage.getItem("bio");
localStorage.setItem("last", location.hash);
document.cookie = "pref=" + location.search;
// 50-52 script URLs, dynamic import
new Worker(location.hash.slice(1));
import(location.hash.slice(1));
import("./static.js"); import(chunkPath);
// 54 tainted variable passed to setTimeout
var code1 = location.hash.slice(1); setTimeout(code1, 10);
// 56 Angular compiled [innerHTML]
ɵɵproperty("innerHTML", ctx.html);
