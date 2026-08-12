# Frontend Guide

| Version | Date | Changes |
|---|---|---|
| 1.11.0 | 2026-08-12 | Risk: ô Debug hiện rule đã cấp quyền cho từng dòng |
| 1.10.0 | 2026-08-12 | Risk: mỗi IP/network một dòng thay vì mỗi object một dòng |
| 1.9.0 | 2026-08-12 | Risk: xuất "Exposure by object" ra PDF qua print stylesheet |
| 1.8.0 | 2026-08-12 | Risk: xuất "Exposure by object" ra CSV |
| 1.7.0 | 2026-08-11 | Search: bảng vùng cho subnet, `partial` cho protocol=any, cột Protocol |
| 1.6.0 | 2026-08-11 | Who reaches a port: thêm ô "Hide traffic out to the internet", mặc định bật |
| 1.5.0 | 2026-08-10 | Access map: chuột phải để ẩn zone. Bảng Inventory giới hạn 300 dòng |
| 1.4.0 | 2026-08-10 | Nạp nhiều firewall, tab Across firewalls, cột Firewall trong Inventory/Risk |
| 1.3.0 | 2026-08-10 | Risk: chỉ liệt kê object có rủi ro; bỏ mục địa chỉ trống ở cả frontend lẫn backend |
| 1.2.0 | 2026-08-10 | Thêm trang Risk: 4 tiêu chí phơi nhiễm, tra theo port, địa chỉ trống, deny-all |
| 1.1.0 | 2026-08-10 | Access map: kéo node tự do, click node để lọc luồng liên quan |
| 1.0.0 | 2026-08-10 | Kiến trúc ban đầu: SPA tĩnh, API_URL đọc lúc runtime |

## Stack

Vite 8, React 18, TypeScript strict, **Tailwind v4**, shadcn/ui, TanStack Query,
react-router 7, `@xyflow/react`. Test bằng Vitest 4 và Testing Library. Build ra
`dist/` tĩnh, nginx serve. Không có node runtime trong production.

## Chạy và test

```
cp .env.example .env
docker compose up -d --build     # production, http://localhost:8011
npm install && npm run dev       # phát triển
npm run test                     # test
npm run lint                     # tsc --noEmit
```

## Biến môi trường

| Tên | Bắt buộc | Mô tả |
|---|---|---|
| `WEB_PORT` | không | Port host, mặc định **8011** |
| `API_URL` | không | Địa chỉ backend, mặc định `http://localhost:8010` |

`API_URL` được entrypoint ghi vào `/usr/share/nginx/html/config.js` lúc container
start. `index.html` nạp file này trước bundle. Đổi backend chỉ cần sửa `.env` rồi
`docker compose up -d`.

## Design system

Token nằm ở `design-system/pfsense-network-map/MASTER.md`, đưa vào
`src/index.css` dưới dạng biến CSS + khối `@theme inline` của Tailwind v4.

**Hai chỗ cố ý không theo MASTER.md:**

1. Style nó chọn là "Exaggerated Minimalism" (`clamp(3rem,10vw,12rem)`,
   `font-weight: 900`). Mục "Best For" của chính style đó ghi *fashion,
   portfolios, agency landing pages*. Đây là công cụ ops đọc-only với bảng dày
   đặc, nên chỉ lấy màu, cặp font và thang spacing density 8.
2. Nó đề xuất nạp font từ Google Fonts CDN — vi phạm yêu cầu offline. Dùng Geist
   đóng gói npm (`@fontsource-variable/geist`) thay thế.

Có **hai token border** vì lý do khác nhau: `--border` (xanh nhạt) chỉ để phân
tách dòng bảng nên nhạt là được; `--input` đậm hơn vì WCAG 1.4.11 yêu cầu viền
control đạt tương phản 3:1 với nền — giá trị trong palette sẽ gần như vô hình.

## Quy ước

- **Không** đọc `API_URL` qua `import.meta.env`. Làm vậy nhúng cứng vào bundle và
  phá yêu cầu đổi URL không rebuild. Luôn dùng `src/lib/config.ts`.
- `configId` nằm trong URL (`/c/:configId/...`). Đó là toàn bộ state cần chia sẻ
  giữa các trang; không có store toàn cục.
- Mọi `<button>` trong `<form>` phải có `type` tường minh.
- Địa chỉ, CIDR và port dùng class `.tabular` (font mono) để căn cột thẳng hàng.
- Bảng dữ liệu giữ tĩnh, không animation.

## Access map: kéo và lọc

Node kéo được tự do; vị trí giữ trong state của `PositionedCanvas`. Click một
node thì chỉ giữ lại các cạnh chạm node đó và ẩn những node còn lại; click lại
node đó, click ra nền, hoặc bấm "Show all zones" để bỏ lọc.

Lọc **ẩn** node chứ không loại khỏi mảng. Loại khỏi mảng sẽ khiến layout dựng
lại và xoá sạch vị trí người dùng vừa kéo. `FlowCanvas` nhận `visibleNodeIds` và
`visibleEdgeIds`; `null` nghĩa là hiện tất cả.

Layout chỉ dựng lại khi **tập id node** đổi, thực hiện bằng `key` trên
`PositionedCanvas`. Đừng thay bằng `useEffect` phụ thuộc mảng `nodes` — identity
của mảng đổi mỗi lần cha re-render.

Node đang focus luôn hiển thị kể cả khi không có luồng nào, nếu không thì click
vào một zone không có luồng sẽ làm chính nó biến mất ngay dưới con trỏ.

## Trang Risk

Bốn bảng trên cùng một trang, nên mỗi bảng phải có `aria-label` — không có tên
thì screen reader chỉ đọc được "table". Đó cũng là cách test trỏ đúng bảng khi
cùng một chuỗi (ví dụ một CIDR) xuất hiện ở nhiều bảng.

Cột phơi nhiễm hiển thị kèm **danh sách port**, không chỉ dấu tick. Biết "lộ ra
internet" mà không biết cổng nào thì vẫn phải mở lại trang Search để tra.

Mỗi dòng là **một IP/network**, không phải một object: một alias có thể chứa host
hở toang bên cạnh host đóng kín, gộp thành một dòng thì phải chọn một câu chuyện
cho cả hai. Cột "Object" chỉ để biết địa chỉ đó thuộc về đâu.

Backend chỉ trả về địa chỉ có vi phạm, nên frontend **không lọc lại** — thêm bộ
lọc ở đây sẽ là hai nguồn sự thật cho cùng một câu hỏi.

Ô **Debug** chèn thêm một dòng dưới mỗi phát hiện, liệt kê rule đã cấp quyền cho
từng tiêu chí. Dữ liệu luôn có sẵn trong response nên bật/tắt không gọi lại API.

Nhãn network xuất hiện ở hai cột khác nhau ("tới các network này" và "được các
network này vào"), nên trong test đừng tìm dòng bằng tên object: "LAN" vừa là tên
object vừa là tên network ở dòng khác. Tìm bằng địa chỉ.


## Nhiều firewall

Trang Upload **không tự chuyển trang** sau khi nạp xong — đó là chỗ duy nhất
nạp được firewall thứ hai, tự nhảy đi sẽ khiến không ai tìm thấy tính năng.
Bấm "Open the map" để đi tiếp.

Nhãn của ô chọn file giữ chữ "config.xml" ở **cả hai** trạng thái. Đổi hẳn sang
"Add another firewall" làm mất manh mối duy nhất mà screen reader có về loại
file cần chọn.

Tab đầu của Search là "Across firewalls" (đi hết chuỗi). Ba tab còn lại vẫn tính
trên **một** firewall — hữu ích khi muốn soi riêng một bộ rule.

### Search có hai dạng kết quả, và `partial` phải trông khác `pass`

`/query/check` và `/query/path` trả `kind: "point"` hoặc `kind: "regions"`. Nhập
một host thì được verdict đơn kèm trace; nhập subnet/alias/interface thì được
**bảng vùng**, mỗi dòng một phần của không gian với verdict riêng. Dòng
`192.168.1.50/32 → BLOCK` bên cạnh phần còn lại của /24 `→ PASS` chính là thứ mà
verdict đơn che mất.

Với `protocol=any`, backend trả `partial` khi các giao thức không đồng ý nhau.
Màu của `partial` **không** dùng màu của `pass` — đọc nhầm partial thành "được
phép" đúng là lỗi cần chặn. Kèm theo là một banner nói thẳng "Partial, not
allowed" và bảng breakdown từng giao thức.

Khi có breakdown, dòng "Decided by rule #…" đơn lẻ bị ẩn: nó lấy từ
`decided_by` tổng, nên với `partial` nó nói "no rule matched" ngay bên dưới
breakdown vừa chỉ rõ tcp được rule #1 cho qua — hai câu mâu thuẫn trên cùng màn
hình.

Cột "Protocol" ở tab From/To hiện `all` khi vùng đúng cho mọi giao thức, và hiện
tên giao thức khi vùng chỉ đúng cho riêng nó.

## Xuất CSV: dữ liệu trong file là của người khác

`src/lib/csv.ts` dùng cho nút Export CSV ở trang Risk. Hai chỗ dễ bỏ sót:

- **CSV injection.** Mô tả interface và tên alias lấy nguyên từ `config.xml` do
  người dùng nạp lên. Một mô tả bắt đầu bằng `=`, `+`, `-`, `@` sẽ được Excel và
  Google Sheets **chạy như công thức** khi mở file. `csvField()` chèn một dấu
  nháy đơn phía trước để vô hiệu hoá.
- **BOM.** Không có `\uFEFF` ở đầu file thì Excel đọc UTF-8 thành mojibake, một
  interface đặt tên tiếng Việt sẽ hỏng. `Blob.text()` **tự bỏ** BOM khi decode,
  nên muốn kiểm chứng phải đọc byte thô qua `arrayBuffer()` — kiểm bằng
  `text()` sẽ luôn báo là thiếu BOM dù nó có ở đó.

Mỗi cờ được xuất thành **hai** cột: cờ (`yes`/`no`) và cổng. Gộp thành một ô
`yes (443, 8443)` như trên giao diện thì bảng tính không lọc hay sắp xếp được.

Bảng chỉ hiện object có rủi ro, và file xuất ra đúng những dòng đó — không phải
toàn bộ object đã kiểm.

## Xuất PDF: dùng chính trình duyệt

Nút "Export PDF" gọi `window.print()`, phần còn lại nằm ở khối `@media print`
trong `src/index.css`. Chọn cách này thay vì nhúng thư viện PDF vì hai lý do:
bundle không tăng một byte nào, và **tiếng Việt hiển thị đúng miễn phí** — thư
viện PDF phía client dùng font WinAnsi mặc định, muốn viết được "Kết nối" thì
phải nhúng thêm một TTF Unicode, cộng cả thư viện lẫn font là 600KB–1MB vào
bundle 258KB hiện tại.

Vùng được in đánh dấu bằng `data-print-region`; thứ cần ẩn dùng
`data-print-hide`. Anh-em của vùng in bị ẩn theo cấu trúc chứ không liệt kê tay,
để thêm một section mới vào trang không âm thầm lọt vào PDF.

**Cạm bẫy đã mắc:** rule ẩn anh-em ban đầu viết là
`main > div > *:not([data-print-region])`. Trang nào không có vùng in — Topology,
Search, Inventory — sẽ khớp toàn bộ và **in ra trắng hoàn toàn**. Phải bọc bằng
`main:has([data-print-region])` để rule chỉ áp cho trang thật sự có vùng in.

`print-color-adjust: exact` là bắt buộc: mặc định trình duyệt bỏ màu khi in, mà
màu đỏ đánh dấu phơi nhiễm chính là thứ không được mất.

## Hiệu năng: chỗ nặng không nằm ở GPU

Đo trên config 3000 rule: trang đồ thị trả về **26 KB, 16 node** — trình duyệt
vẽ xong tức thì, thời gian chờ là backend tính. Trang nặng thật là **Inventory**,
vì `/rules` trả 1,18 MB và dựng vài nghìn dòng DOM.

Nên cách sửa là **giới hạn số dòng** (300, cắt trong chính component `Table` nên
áp cho cả bốn tab), không phải bật GPU. Số dòng bị bỏ luôn được in ra — một bảng
lặng lẽ dừng ở dòng 300 gây hiểu nhầm tệ hơn nhiều so với một bảng chậm.

Đừng thêm `will-change: transform` để "tăng tốc GPU" mà không đo trước. React
Flow đã dùng CSS transform cho viewport, phần đó vốn đã do GPU composite.

## Access map: ẩn zone

Chuột phải vào một zone mở menu ẩn nó cùng mọi luồng chạm nó. Ẩn khác với focus:
focus là "chỉ xem cái này", ẩn là "đừng bao giờ cho tôi thấy cái này"; hai bộ lọc
cộng dồn được.

Menu đóng được bằng **Escape** lẫn click ra ngoài. Chỉ có click ra ngoài thì
người dùng bàn phím bị kẹt.

Mục trong menu mang `role="menuitem"`, không phải `role="button"` — đó là hình
dạng ARIA đúng, nên test phải query theo `menuitem`.

## Gotchas

- **`docker compose restart` không nạp lại env.** Dùng `up -d` để tạo lại container.
- **Compose project name phải đặt tường minh** (`name:` trong `docker-compose.yml`),
  cùng lý do như backend: mặc định Compose lấy tên thư mục `frontend`, quá chung,
  và sẽ nhận container của project khác cùng tên thư mục làm orphan.
- **Font phải import từ `main.tsx`, không phải `index.css`.** Đặt
  `@import "@fontsource-variable/geist"` trong `index.css` khiến Tailwind xử lý
  `@import` đó, Vite không rewrite `url(./files/*.woff2)`, và **không file woff2
  nào vào `dist/`** — mọi request font 404 lúc chạy, âm thầm rơi về system font.
- **React Flow đo kích thước container lúc mount.** jsdom không có
  `ResizeObserver` và báo mọi element là 0x0, nên `src/vitest.setup.ts` phải stub
  cả ba: `ResizeObserver`, `offsetWidth`, `offsetHeight`.
- **Kiểm chứng kéo node bằng script phải chờ React re-render.** Đọc
  `node.style.transform` ngay sau khi bắn `mouseup` luôn trả về vị trí cũ và làm
  ta tưởng kéo hỏng. Chờ một nhịp (`setTimeout`) rồi mới đọc. React Flow v12 gắn
  `mousedown.drag` — dùng `MouseEvent`, không phải `PointerEvent`.
- **React Flow không render nhãn cạnh trong jsdom** vì node chưa được đo. Đó là
  một phần lý do trang Access map có thêm danh sách "Allowed flows" bên dưới
  canvas — lý do chính là canvas không đọc được bằng screen reader.
- **Backend giữ config trong RAM.** Sau khi backend restart, mọi `configId` trong
  URL đều trả 404; các trang hiển thị lỗi đó và người dùng phải upload lại.
- shadcn CLI hiện sinh code cho Tailwind v4. Đừng hạ về v3 — sẽ phải tự bảo trì
  toàn bộ bảng ánh xạ token.
