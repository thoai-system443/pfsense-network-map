# Backend Guide

| Version | Date | Changes |
|---|---|---|
| 1.9.0 | 2026-08-11 | `risk/port` thêm `hide_internet_destinations`, mặc định bật |
| 1.8.0 | 2026-08-10 | Cache parse CIDR, dựng sẵn tập địa chỉ của region, nội tuyến phép giao hình chữ nhật |
| 1.7.0 | 2026-08-10 | Cache resolver và explore_from: access-graph 1.34s → 0.13s trên 3000 rule |
| 1.6.0 | 2026-08-10 | Workspace nhiều firewall, bảng định tuyến, tính đường đi xuyên firewall |
| 1.5.0 | 2026-08-10 | Bỏ hẳn `unoccupied_grants` khỏi engine và API |
| 1.4.0 | 2026-08-10 | Action `match` không quyết định verdict; nhận `source_hash_key`/`ipprotocol` của outbound NAT |
| 1.3.0 | 2026-08-10 | Thêm `engine/risk.py`: 4 tiêu chí phơi nhiễm, tra theo port, khoảng địa chỉ trống, kiểm tra deny-all |
| 1.2.0 | 2026-08-10 | `CORS_ORIGINS` nhận chuỗi thô và danh sách phẩy, có kiểm tra định dạng |
| 1.1.0 | 2026-08-10 | Nhận diện `srcmac`/`dstmac`/`bridgeto` từ config thật đầu tiên, kèm cảnh báo "không mô phỏng" |
| 1.0.0 | 2026-08-10 | Kiến trúc ban đầu: parser, engine, API stateless |

## Stack

Python 3.12, FastAPI, pydantic v2, pydantic-settings, uvicorn (một worker),
nginx, Docker Compose. **Không có database.** pytest và ruff cho test và lint.

## Bố cục

```
app/parser/   chỉ hiểu XML, cho ra kiểu dữ liệu trong app/parser/types.py
app/engine/   chỉ làm việc trên kiểu dữ liệu đó, không bao giờ chạm XML
app/api/      ghép hai tầng kia với HTTP
```

Ranh giới này cho phép test engine bằng object dựng tay, không cần file XML.
`app/parser/xmlutil.py` giữ các helper XML dùng chung, tách khỏi `loader.py` để
các parser con không phải import vòng qua loader.

## Chạy và test

```
cp .env.example .env
docker compose up -d --build
./test.sh                     # pytest trong container api
```

Phát triển nhanh hơn thì dùng venv cục bộ:

```
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
.venv/bin/ruff check app tests
```

nginx là container duy nhất publish port. uvicorn không bind ra host.

## Biến môi trường

| Tên | Bắt buộc | Mô tả |
|---|---|---|
| `API_PORT` | không | Port host cho nginx, mặc định **8010** |
| `DOCS_USER` | **có** | Tài khoản Basic auth cho `/api/v1/docs` |
| `DOCS_PASSWORD` | **có** | Mật khẩu Basic auth. Entrypoint fail fast nếu thiếu |
| `CORS_ORIGINS` | không | Origin được phép, mặc định `http://localhost:8011`. Xem bên dưới |

### CORS_ORIGINS

Nhận ba cách viết, kết quả như nhau:

```
CORS_ORIGINS=http://localhost:8011
CORS_ORIGINS=http://localhost:8011, https://map.example.com
CORS_ORIGINS=["http://localhost:8011"]
```

Mỗi giá trị phải là `scheme://host[:port]`. Dấu `/` cuối bị bỏ; có đường dẫn hoặc
thiếu scheme thì bị từ chối kèm thông báo nêu đúng giá trị sai. `*` được giữ
nguyên. Trình duyệt gửi header `Origin` không có đường dẫn và không có `/` cuối,
nên một giá trị lưu sai định dạng sẽ **không bao giờ khớp** — chặn sớm lúc khởi
động dễ chẩn đoán hơn nhiều so với lỗi CORS mơ hồ trên trình duyệt.

`Annotated[list[str], NoDecode]` trong `app/settings.py` là bắt buộc, không phải
trang trí: thiếu nó, pydantic-settings JSON-decode giá trị env ngay trong settings
source, **trước** khi validator chạy, và mọi cách viết không phải JSON đều chết ở
đó bằng `SettingsError`. Test phải đi qua biến môi trường thật
(`monkeypatch.setenv`) — dựng `Settings(...)` bằng constructor đi đường khác và
bỏ qua đúng tầng gây lỗi.

## Hiệu năng

Đo trên config tổng hợp 16 interface / 3000 rule / 60 alias (`/tmp/big.xml`
sinh bằng script trong lịch sử commit):

| Endpoint | Ban đầu | Hiện tại |
|---|---|---|
| `access-graph` | 1.34s | **0.08s** |
| `risk` | 0.74s | **0.29s** |
| `risk/port` | 0.05s | 0.05s |
| `topology` | 0.01s | 0.01s |

Năm chỗ tốn, tất cả tìm ra bằng `cProfile` chứ không bằng phỏng đoán:

1. **`Resolver` parse lại chuỗi CIDR cho từng rule.** `interface_subnet` bị gọi
   96.000 lần trong một lần dựng access-graph. Giờ `Resolver` cache subnet, IP
   interface, `(self)` và alias đã expand. Alias lồng nhau **không** cache khi
   đang trong chuỗi đệ quy, nếu không phát hiện vòng lặp sẽ hỏng.
2. **`access_graph` gọi `explore_from` cho từng cặp zone.** 17 zone → 256 lần
   thay vì 16. `_Memo` cache theo `(firewall, source, protocol, in_interface)`;
   với cùng một zone nguồn thì khoá giống nhau ở mọi đích.

3. **`IpSet.from_cidr` parse lại cùng một chuỗi.** 74.000 lần trong một lần dựng
   risk report. `_parse_cidr` trong `ipset.py` cache bằng `lru_cache` và chỉ trả
   về **số nguyên**, không bao giờ trả IpSet — cache một object có `list` bên
   trong sẽ chia sẻ mảng mutable cho mọi caller.
4. **`risk.exposures` dựng lại tập địa chỉ của từng region cho từng subject.**
   `_allowed_from` giờ trả `(region, IpSet)` đã dựng sẵn một lần.
5. **`RectSet.intersect` gọi hai method cho mỗi cặp hình chữ nhật.** 1,39 triệu
   cặp; phép so sánh biên rẻ hơn chi phí gọi hàm, nên nội tuyến luôn. `Rect` thêm
   `slots=True`.

Bài học đáng nhớ: giả thuyết đầu tiên ("gọi lặp explore_from") **sai** — thêm
cache mà không đo lại cho ra đúng 1.36s so với 1.34s. Chỗ thật sự tốn là parse
CIDR. Profile trước, sửa sau.

## Nhiều firewall

Một `config_id` là một **workspace** chứa nhiều firewall, không phải một file.
`POST /configs/{id}/firewalls` nạp thêm; file được parse xong mới gắn vào, nên
upload hỏng không làm hỏng workspace.

`app/engine/fabric.py` lo phần nhiều firewall. Chuỗi suy ra từ **next-hop của
bảng route**: firewall nào sở hữu địa chỉ đó là chặng kế tiếp. Verdict `pass`
chỉ khi mọi chặng cho qua; chặng đầu tiên từ chối là chặng được báo.

Ba điểm phải giữ đúng:

- **`_owner_of` quét khớp-chính-xác trên toàn bộ firewall trước** rồi mới tới
  khớp-subnet. Làm cả hai lần lượt trong từng firewall sẽ khiến chính firewall
  đang rời đi nhận lấy subnet transit của nó và chuỗi đứt ngay chặng đầu, vì
  next-hop luôn nằm trong đoạn mạng hai bên dùng chung.
- **Next-hop thuộc thiết bị không được nạp thì chuỗi dừng và `truncated=True`.**
  Kết luận "thông" cho cả đường khi chưa kiểm là điều công cụ này không có bằng
  chứng để nói.
- **`shared` là thuộc tính riêng, không phải một giá trị của `kind`.** `kind`
  nói segment là gì (interface/vlan/tunnel), `shared` nói mấy firewall chạm vào.
  Gộp hai thứ vào một trường làm mất cờ VLAN.

`/risk` chạy **từng firewall một** và gắn nhãn, vì bốn tiêu chí phơi nhiễm hỏi
về một bộ rule cụ thể. Khả năng tới được xuyên firewall là việc của `query/path`.

## Ngữ nghĩa đánh giá rule

Đây là phần lõi, và là chỗ dễ mô phỏng sai nhất.

1. Xác định interface vào từ IP nguồn — mạng khớp prefix dài nhất. Danh sách ứng
   viên gồm **cả subnet của interface lẫn dải mạng của tunnel VPN**, vì pfSense
   gắn rule của tunnel vào pseudo-interface `openvpn` / `enc0` chứ không phải một
   interface được cấu hình. Không có mạng nào khớp thì rơi về `wan`.
2. Ruleset = floating rules (khớp interface, direction `in`/`any`) → rule của
   chính interface → implicit anti-lockout rule trên LAN. Rule `disabled` bị loại
   ngay từ bước dựng.
3. Duyệt tuần tự, giữ `last_match`: rule khớp **và** `quick` thì trả ngay; rule
   khớp nhưng không `quick` thì ghi lại rồi đi tiếp. Hết ruleset mà chưa từng
   khớp thì **default deny**.
4. NAT đích (port forward, 1:1) áp **trước** khi lọc. Rule cho phép phải trỏ tới
   IP nội bộ đã dịch, không phải IP public.

`explore_from` / `explore_to` chạy đúng luật trên nhưng trên toàn bộ không gian
(địa chỉ × port) bằng phép trừ tập hai chiều, nên kết quả đầy đủ chứ không phải
liệt kê mẫu. Test `test_explore_agrees_with_point_check_on_sampled_points` chốt
rằng hai đường tính này luôn cho cùng kết quả.

## Quy ước

- Route chữ cố định khai báo trước route `/{id}` cùng cấp.
- Dependency dùng `Annotated[T, Depends(...)]` (`ConfigDep` trong
  `app/api/v1/configs.py`), không gọi `Depends()` trong default argument — ruff
  B008 bắt đúng chỗ đó.
- Parser không im lặng bỏ qua field lạ: mọi phần tử không nhận diện được sinh một
  `ParseWarning` và đi lên tận response upload.
- IPv4 và IPv6 nằm trong hai không gian tách biệt. Mọi phép toán trộn hai họ đều
  ném lỗi.
- Alias `url` và `urltable` không được fetch. Chúng cho tập rỗng và đánh dấu kết
  quả là `unresolved`.
- `PortSet.to_spec()` và `PortSet.parse()` round-trip được, kể cả `"any"` và
  `"none"`.

## Gotchas

- **`docker compose restart` không nạp lại env.** Dùng `up -d` để tạo lại container.
- **Chỉ chạy một worker uvicorn.** Store nằm trong RAM tiến trình; nhiều worker sẽ
  khiến request rơi vào process không giữ config.
- **Compose project name phải đặt tường minh** (`name:` trong `docker-compose.yml`).
  Mặc định Compose lấy tên thư mục — ở đây là `backend`, quá chung. Máy dev này
  đã có một project khác cũng nằm trong thư mục `backend`; container của nó bị
  coi là orphan của project này và **`docker compose down --remove-orphans` sẽ
  xoá mất**. Đừng bỏ dòng `name:`, và đừng chạy `--remove-orphans` ở đây.
- **`nginx:alpine` không có `openssl`.** Image nginx được build từ
  `nginx/Dockerfile` để cài lúc build, giữ runtime air-gapped.
- **`set -e` không bắt command substitution hỏng nằm trong tham số `printf`.**
  Entrypoint vì vậy kiểm tra hash tường minh; bản đầu tiên ghi ra `.htpasswd` cụt
  và trả 401 cho mọi request mà không báo lỗi gì.
- **Floating rule mặc định không `quick`, interface rule thì có.** Đây là lý do
  một floating rule khớp vẫn có thể bị interface rule đứng sau ghi đè. Đừng "sửa"
  thành first-match-wins.
- **Outbound NAT không ảnh hưởng verdict** và không được đưa vào engine đánh giá.
- Tập địa chỉ được chuẩn hoá: `to_cidrs()` trả vùng phủ CIDR tối thiểu, nên hai
  host liền kề `.10` và `.11` hiện ra thành `.10/31` chứ không phải hai `/32`.

## Phân tích rủi ro

`app/engine/risk.py` **không** quyết định thêm bất kỳ điều gì về ngữ nghĩa `pf`.
Mọi kết luận đều gọi `evaluate.explore_from`, nên một cảnh báo ở đây không bao
giờ mâu thuẫn với kết quả trang Search cho cùng luồng traffic. Muốn sửa hành vi
đánh giá thì sửa `evaluate.py`, đừng sửa ở đây.

Đối tượng phân tích (`subjects`) gồm: interface đang bật, tunnel VPN, và alias
loại `host`/`network`.

| Hàm | Trả lời |
|---|---|
| `exposures` | 4 tiêu chí cho từng đối tượng |
| `port_reachability` | Nguồn nào tới được bất cứ đâu trên một port |

`port_reachability(hide_internet_destinations=True)` — mặc định — chỉ cắt
**chiều đi ra**: bỏ những dòng có đích nằm ngoài dải địa chỉ của hệ thống. Một
rule cho phép ra internet mặc định sẽ nhồi bảng bằng "LAN tới cả internet trên
443" và vùi mất phần còn lại.

**Chiều từ internet đi vào luôn được giữ**, ở cả hai chế độ. Đó là phơi nhiễm
inbound — thứ quan trọng nhất mà tra cứu này nói được. Luồng nội bộ ↔ nội bộ
cũng giữ nguyên.

Bản đầu tiên bỏ internet ở **cả hai** đầu và vì thế giấu mất chính thông tin
đáng giá nhất. Đừng "tối ưu" lại theo hướng đó.
| `deny_all_audit` | Block-all không chặn thật, và rule chết sau block-all |

Điểm cần biết khi đọc kết quả:

- **"Reachable from every internal zone"** không tính internet. Tiêu chí này đo
  bán kính lây lan nội bộ; nguồn từ WAN không được làm một host trông như thể ai
  bên trong cũng tới được.

## Action `match`

pfSense có bốn action, không phải ba: `pass`, `block`, `reject` và **`match`**.
`match` dùng cho floating rule gắn queue/limiter — nó khớp traffic nhưng **không
quyết định gì**, đánh giá đi tiếp xuống rule dưới.

`evaluate.decides()` là chỗ duy nhất chốt điều này, và cả `check`,
`explore_from`, `explore_to` đều đi qua nó. Rule `match` vẫn nằm trong trace và
trong danh sách rule của Inventory, vì nó **có** được đánh giá — chỉ là không
định đoạt kết quả.

Đây là lỗi thật đã xảy ra: bản đầu quy mọi action lạ về `block`, nên một floating
`match` any→any (rất phổ biến khi bật traffic shaper) bị mô phỏng thành chặn sạch
toàn bộ interface. Công cụ báo "block" trong khi firewall vẫn cho traffic đi —
kiểu sai nguy hiểm nhất, vì nó khiến người đọc yên tâm nhầm.

## Field thu hẹp rule mà engine không mô phỏng

Một rule có thể khớp **ít** packet hơn phần địa chỉ và port gợi ý. Engine bỏ qua
những field đó, nên mọi verdict rút ra từ rule như vậy chỉ có thể **rộng hơn**
thực tế, không bao giờ chặt hơn. Danh sách nằm ở `NARROWING_FIELDS` trong
`app/parser/rules.py`; mỗi lần gặp, parser sinh một `ParseWarning` nói rõ điều đó.

| Field | Thu hẹp theo |
|---|---|
| `srcmac` | Địa chỉ MAC nguồn |
| `dstmac` | Địa chỉ MAC đích |
| `bridgeto` | Interface thành viên bridge |

Gặp field thu hẹp mới trong config thật thì thêm vào **cả hai**:
`KNOWN_RULE_CHILDREN` (để hết báo "unrecognised") và `NARROWING_FIELDS` (để vẫn
cảnh báo). Chỉ thêm vào danh sách thứ nhất là biến một giới hạn đã biết thành một
lỗi im lặng.

## Chưa kiểm chứng

Parser viết theo schema pfSense 2.7. Lần đối chiếu đầu tiên với config thật đã
phát hiện ba field thiếu (`srcmac`, `dstmac`, `bridgeto`) — cơ chế `ParseWarning`
hoạt động đúng như thiết kế. Vẫn còn hai chỗ rủi ro:

1. **Tên field** trong các hằng `KNOWN_*_CHILDREN` của từng module parser. Danh
   sách `warnings` trong response upload sẽ chỉ ra ngay chỗ thiếu — đó là lý do
   cơ chế cảnh báo tồn tại. Xem `warnings` trước khi tin kết quả.
2. **Interface group.** `ruleset.build` xử lý group bằng cách so tên group với
   tên interface, nhưng chưa có fixture vì chưa biết cấu trúc `<ifgroups>` thật.

## Ngoài phạm vi

Không đọc gateway và static route, nên subnet nằm sau router nội bộ sẽ không lên
bản đồ. Không có khái niệm user. Không traffic shaper. Không mô phỏng state table
hay reply traffic. Không so sánh hai bản backup.
