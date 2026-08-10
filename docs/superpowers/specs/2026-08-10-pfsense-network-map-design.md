# pfSense Network Map — Thiết kế

| | |
|---|---|
| Ngày | 2026-08-10 |
| Trạng thái | Đã duyệt, chờ lập kế hoạch triển khai |

## 1. Mục tiêu

Một ứng dụng chạy hoàn toàn offline, đọc file backup `config.xml` của pfSense và trả lời được:

1. Mạng này trông như thế nào (interface, VLAN, subnet, tunnel VPN).
2. IP / network / port nào được phép đi tới IP / network / port nào.
3. Tra cứu hai chiều: từ một nguồn đi được tới đâu, và ai tới được một đích.
4. Liệt kê và lọc toàn bộ đối tượng theo IP / network / port.

## 2. Ngoài phạm vi

Những mục dưới đây **không** làm, đã thống nhất khi brainstorm:

- Không đọc gateway và static route. Hệ quả: subnet nằm sau một router nội bộ sẽ không xuất hiện trên bản đồ. Chỉ những subnet gắn trực tiếp vào pfSense (interface, VLAN, tunnel) mới được vẽ.
- Không có khái niệm "user". Chỉ làm việc với IP, subnet, alias, port. Không đọc user VPN, không đọc `<system><user>`, không đọc DHCP static mapping.
- Không đọc traffic shaper / limiter.
- Không mô phỏng state table, không xét reply traffic. Mọi đánh giá là cho packet đầu tiên của một kết nối.
- Không so sánh hai bản backup.
- Không có cơ sở dữ liệu. Không lưu trữ lâu dài.

## 3. Kiến trúc

Hai stack độc lập, mỗi stack có `docker-compose.yml` riêng và chạy được một mình. Không có compose ở thư mục gốc. Frontend không proxy sang backend; SPA gọi thẳng backend qua port riêng của nó, backend bật CORS.

```
pfsense-network-map/
├─ backend/          # FastAPI, stateless. compose: api + nginx
├─ frontend/         # Vite + React + TS. compose: 1 container nginx serve dist/
├─ docs/superpowers/specs/
├─ BACKEND_GUIDE.md
├─ FRONTEND_GUIDE.md
└─ design-system/
```

### 3.1 Lệch khỏi convention mặc định

Convention scaffolding của dự án bắt buộc PostgreSQL + SQLAlchemy + Alembic. Dự án này **bỏ toàn bộ tầng đó** theo yêu cầu rõ ràng của người dùng: bản chất bài toán là nạp một file XML rồi phân tích trong RAM, dựng DB cho một document duy nhất là thừa.

Hệ quả phải chấp nhận:

- Backend giữ `dict[config_id] -> ParsedConfig` trong bộ nhớ tiến trình. Restart container là mất, phải upload lại.
- Chỉ chạy được **một worker uvicorn**. Nhiều worker sẽ khiến request rơi vào process không có config. Ghi rõ trong `BACKEND_GUIDE.md`.
- `test.sh` không cần tạo database test; chỉ chạy pytest trong container api.

Mọi convention còn lại giữ nguyên: nginx là container duy nhất publish port, uvicorn không publish ra host, nginx bắt HTTP Basic auth cho `/api/v1/docs|redoc|openapi.json` với `DOCS_USER` / `DOCS_PASSWORD`, entrypoint fail fast nếu thiếu biến môi trường, secret chỉ nằm trong `.env` (gitignore) và `.env.example` được commit.

### 3.2 Hoạt động offline

- Không CDN font, không map tile, không gọi mạng ngoài ở cả build lẫn runtime.
- Toàn bộ thư viện được bundle vào `dist/`.
- Sau khi kéo image một lần, hệ thống chạy được trong môi trường air-gapped.

## 4. Backend

### 4.1 Bố cục

```
backend/
├─ docker-compose.yml        # api + nginx
├─ Dockerfile
├─ nginx/{nginx.conf, entrypoint.sh}
├─ pyproject.toml            # ruff, pytest
├─ test.sh
├─ .env.example
├─ app/
│  ├─ main.py                # FastAPI app, CORS, mount router v1
│  ├─ settings.py            # pydantic-settings
│  ├─ store.py               # in-memory store, TTL + giới hạn số config
│  ├─ api/v1/
│  │  ├─ configs.py          # upload / xem / xoá
│  │  ├─ inventory.py        # interfaces, aliases, rules, nat
│  │  ├─ maps.py             # topology, access-graph
│  │  └─ query.py            # check / from / to
│  ├─ parser/
│  │  ├─ loader.py           # XML -> tree, dò version, gom warning
│  │  ├─ interfaces.py       # interfaces + vlans
│  │  ├─ aliases.py
│  │  ├─ rules.py            # filter rules + floating
│  │  ├─ nat.py              # port forward, 1:1, outbound
│  │  ├─ vpn.py              # openvpn, ipsec
│  │  └─ types.py            # pydantic model của ParsedConfig
│  └─ engine/
│     ├─ ipset.py            # tập dải IP rời rạc, v4 và v6 tách riêng
│     ├─ portset.py          # tập dải port rời rạc
│     ├─ rect.py             # tập 2D (địa chỉ × port), hợp và trừ
│     ├─ resolver.py         # alias / keyword -> IpSet, phát hiện vòng lặp
│     ├─ ruleset.py          # dựng ruleset đã sắp xếp cho một interface vào
│     ├─ nat.py              # áp NAT trước filter
│     ├─ evaluate.py         # point check + explore
│     └─ graph.py            # topology graph + access graph
└─ tests/
   ├─ fixtures/*.xml
   └─ test_*.py
```

Nguyên tắc chia module: mỗi file `parser/*` chỉ hiểu một nhánh của XML và trả về kiểu dữ liệu trong `types.py`; mỗi file `engine/*` chỉ làm việc với kiểu dữ liệu đó, không đụng tới XML. Ranh giới này cho phép test engine mà không cần file XML, và test parser mà không cần engine.

### 4.2 Mô hình dữ liệu

`ParsedConfig` gồm:

- `version` — chuỗi version pfSense đọc từ `<version>`, có thể `None`.
- `interfaces: list[Interface]` — `name` (`wan`, `lan`, `opt3`), `descr` (tên hiển thị, ví dụ `DMZ`), `if_` (`em0`, `em0.20`), `ipaddr`, `subnet`, `enabled`, `is_vlan`, `vlan_tag`, `parent_if`.
- `aliases: list[Alias]` — `name`, `type` (`host` | `network` | `port` | `url` | `urltable`), `items: list[str]`, `descr`.
- `rules: list[FilterRule]` — theo thứ tự xuất hiện trong XML. Trường: `seq` (thứ tự gốc), `interfaces: list[str]`, `floating: bool`, `quick: bool`, `direction` (`in` | `out` | `any`), `action` (`pass` | `block` | `reject`), `disabled: bool`, `ipprotocol` (`inet` | `inet6` | `inet46`), `protocol` (`tcp` | `udp` | `tcp/udp` | `icmp` | `any` | khác), `source: AddrSpec`, `destination: AddrSpec`, `descr`, `tracker`.
- `AddrSpec` — `any: bool`, `network: str | None` (CIDR, tên interface, `<if>ip`, `(self)`), `address: str | None` (IP hoặc tên alias), `not_: bool`, `port: str | None` (`80`, `1000-2000`, tên alias port).
- `nat: NatConfig` — `port_forwards: list[PortForward]` (`interface`, `protocol`, `dst`, `dst_port`, `target`, `local_port`, `disabled`, `associated_rule`), `one_to_one: list[OneToOne]`, `outbound: list[OutboundRule]`.
- `vpn: VpnConfig` — `openvpn_servers` / `openvpn_clients` (`vpnid`, `descr`, `tunnel_network`, `local_network`, `remote_network`), `ipsec_phase2` (`descr`, `local_subnet`, `remote_subnet`).
- `warnings: list[ParseWarning]` — mỗi mục gồm `path` (đường dẫn XML), `message`, `severity`.

Parser **không im lặng bỏ qua** field lạ. Mỗi phần tử con không nằm trong danh sách đã biết sẽ sinh một `ParseWarning`. Đây là cơ chế chính để phát hiện thiếu sót khi nạp config thật lần đầu.

### 4.3 Ngữ nghĩa đánh giá rule

Đây là phần lõi. Mô hình bám theo hành vi thật của `pf` trên pfSense, không giả định "first-match-wins" một cách đơn giản.

**Bước 1 — xác định interface vào.** Tìm interface có subnet chứa IP nguồn. Nếu không có subnet nào chứa, coi là đến từ interface WAN. Nếu nhiều subnet chứa, chọn subnet có prefix dài nhất.

**Bước 2 — dựng ruleset theo thứ tự.** Nối theo đúng thứ tự này:

1. Floating rules có `interfaces` chứa interface vào (hoặc rỗng nghĩa là mọi interface) và `direction` là `in` hoặc `any`.
2. Rules của interface group chứa interface vào, nếu config có định nghĩa group.
3. Rules của chính interface vào.
4. Implicit anti-lockout rule trên interface LAN (pass tới địa chỉ LAN, port quản trị).

Rule có `disabled = True` bị loại khỏi ruleset ngay từ bước dựng. Không thêm rule block-all vào ruleset; default deny được xử lý ở bước 3 khi duyệt hết mà không có match nào.

**Bước 3 — luật thắng.** Duyệt tuần tự, giữ biến `last_match`:

- Rule khớp và `quick = True` → trả kết quả ngay.
- Rule khớp và `quick = False` → gán vào `last_match`, tiếp tục duyệt.
- Hết ruleset → trả `last_match`; nếu chưa từng khớp, trả `block` (default deny).

pfSense sinh mọi interface rule kèm `quick`, còn floating rule mặc định **không** `quick`. Mô hình trên vì vậy tái hiện đúng hiện tượng: một floating rule không `quick` bị interface rule đứng sau ghi đè. Đây là hành vi dễ mô phỏng sai nhất và có test riêng bắt buộc phải xanh.

**Bước 4 — khớp một rule.** Rule khớp khi tất cả điều kiện sau đúng: họ địa chỉ (`ipprotocol`) phù hợp; protocol phù hợp (`any` khớp mọi thứ, `tcp/udp` khớp cả hai); tập IP nguồn giao với nguồn truy vấn khác rỗng; tập IP đích giao với đích truy vấn khác rỗng; tập port giao khác rỗng. Cờ `not_` đảo tập địa chỉ tương ứng (lấy phần bù trong toàn bộ không gian địa chỉ của họ đó).

**Giải mã địa chỉ.** `resolver.py` chuyển một `AddrSpec` thành `IpSet`:

- `any` → toàn bộ không gian địa chỉ của họ tương ứng.
- CIDR hoặc IP đơn → chính nó.
- Tên interface (`lan`, `opt3`) → subnet của interface đó.
- `<tên interface>ip` (`lanip`) → đúng một địa chỉ IP của interface.
- `(self)` → tập mọi IP của mọi interface.
- Tên alias → mở rộng đệ quy. Alias `host` và `network` cho ra `IpSet`; alias `port` cho ra `PortSet`. Alias lồng alias được hỗ trợ. Nếu phát hiện vòng lặp, ném lỗi kèm chuỗi alias tạo thành vòng — không được treo hoặc tràn stack.
- Alias loại `url` / `urltable` → không giải được offline. Trả tập rỗng và sinh `ParseWarning`; mọi kết quả liên quan tới rule đó được đánh dấu `unresolved` để hiển thị trên UI.

**Bước 5 — NAT.** Áp trước filter, đúng thứ tự pfSense:

- **Port forward**: nếu đích truy vấn khớp `dst` + `dst_port` của một port forward trên interface vào, đích được dịch thành `target` + `local_port` **trước khi** đem đi khớp ruleset. Nghĩa là rule cho phép phải trỏ tới IP nội bộ, không phải IP public. Kết quả trả về ghi rõ cả đích gốc lẫn đích sau dịch.
- **1:1 NAT**: dịch hai chiều giữa địa chỉ ngoài và địa chỉ trong.
- **Outbound NAT**: chỉ parse và hiển thị, **không** ảnh hưởng tới verdict. Trên pfSense, outbound NAT áp sau khi filter đã quyết định, nên nó đổi source mà bên nhận thấy chứ không đổi việc packet có được đi qua hay không.

### 4.4 Ba loại truy vấn

| Loại | Câu hỏi | Cách tính |
|---|---|---|
| `check` | "A tới B:443 được không?" | Chạy đúng một lượt bước 1–5. Trả verdict, rule đã quyết định (`seq`, interface, `descr`, `tracker`), và trace đầy đủ các rule đã xét. |
| `from` | "A đi được tới đâu?" | Duyệt ruleset của interface chứa A. Giữ một tập 2D "không gian đích chưa chốt" khởi tạo bằng toàn bộ (địa chỉ × port). Với mỗi rule khớp nguồn A, lấy phần giao giữa (đích × port) của rule và không gian chưa chốt, rồi xử lý theo `quick` như mô tả bên dưới. Phần không gian không rule nào khớp là `block` mặc định. |
| `to` | "Ai tới được B:443?" | Lặp thuật toán `from` cho từng interface vào, nhưng trừ trên **không gian nguồn**. |

`from` và `to` cho kết quả **đầy đủ và chính xác**, không phải liệt kê mẫu, vì phép trừ tập bao phủ toàn bộ không gian.

Phân biệt `quick` trong `from` / `to`:

- Rule **có** `quick`: phần giao được gán verdict và **chốt** ngay, trừ khỏi không gian chưa chốt. Rule sau không chạm được vào phần này nữa.
- Rule **không** `quick`: phần giao chỉ được ghi **verdict tạm** (ghi đè verdict tạm cũ nếu có), **không** trừ khỏi không gian chưa chốt. Rule `quick` đứng sau vẫn giành lại được phần này.

Duyệt hết ruleset, phần không gian còn lại chưa chốt: nếu có verdict tạm thì chốt bằng verdict đó, nếu không thì `block` mặc định. Quy tắc này tương đương chính xác với luật `last_match` ở bước 3, chỉ khác là chạy song song trên toàn không gian thay vì trên một điểm.

`rect.py` biểu diễn tập 2D là danh sách các hình chữ nhật (dải địa chỉ × dải port) đôi một rời nhau, hỗ trợ hai phép: hợp và trừ. Địa chỉ IPv4 và IPv6 được giữ trong hai không gian tách biệt để tránh so sánh nhầm.

### 4.5 API

Toàn bộ dưới `/api/v1`.

| Method | Path | Mô tả |
|---|---|---|
| POST | `/configs` | Upload `config.xml` (multipart). Trả `config_id`, `version`, số lượng từng loại đối tượng, `warnings`. |
| GET | `/configs/{id}` | Metadata như trên. |
| DELETE | `/configs/{id}` | Xoá khỏi bộ nhớ. |
| GET | `/configs/{id}/interfaces` | Danh sách interface, VLAN, subnet. |
| GET | `/configs/{id}/aliases` | Danh sách alias. `?resolved=true` trả thêm tập IP/port đã mở rộng. |
| GET | `/configs/{id}/rules` | Danh sách rule theo thứ tự đánh giá. `?interface=` để lọc. |
| GET | `/configs/{id}/nat` | Port forward, 1:1, outbound. |
| GET | `/configs/{id}/topology` | `{nodes, edges}` cho tab Topology. |
| GET | `/configs/{id}/access-graph` | `{nodes, edges}` cho tab Access map. |
| POST | `/configs/{id}/query/check` | Body: `source`, `destination`, `port`, `protocol`. |
| POST | `/configs/{id}/query/from` | Body: `source`, `protocol` (tuỳ chọn). |
| POST | `/configs/{id}/query/to` | Body: `destination`, `port` (tuỳ chọn), `protocol` (tuỳ chọn). |

Trường `source` / `destination` nhận IP đơn, CIDR, tên alias, hoặc tên interface.

Giới hạn: file upload tối đa 16 MB; store giữ tối đa 20 config, quá thì loại config cũ nhất theo thời điểm truy cập gần nhất.

### 4.6 Access graph

Node là một **zone**: mỗi interface đang bật (kèm subnet), mỗi tunnel VPN, cộng node `Internet` đại diện cho phần địa chỉ không thuộc bất kỳ subnet nội bộ nào.

Với mỗi cặp zone có thứ tự `(A, B)`, chạy `from` với nguồn là subnet của A, rồi lấy phần kết quả giao với subnet của B. Nếu có phần nào verdict `pass`, sinh một cạnh `A -> B` kèm danh sách port và danh sách rule sinh ra nó. Cạnh mang theo `rule_refs` để UI cho phép click xem rule.

## 5. Frontend

### 5.1 Bố cục

```
frontend/
├─ docker-compose.yml
├─ Dockerfile                 # node:alpine build -> nginx:alpine serve dist/
├─ nginx/{nginx.conf, entrypoint.sh}   # sinh config.js lúc container start
├─ index.html                 # nạp config.js trước bundle
├─ package.json, vite.config.ts, tsconfig.json, tailwind.config.ts
└─ src/
   ├─ main.tsx, App.tsx, router.tsx
   ├─ lib/{config.ts, api.ts, queryClient.ts}
   ├─ components/ui/          # shadcn/ui
   ├─ components/graph/       # node và edge tuỳ biến cho React Flow
   └─ pages/{Upload,Topology,AccessMap,Search,Inventory}.tsx
```

Stack: Vite + React + TypeScript (`strict: true`) + Tailwind + shadcn/ui + Magic UI (dùng tiết chế, bảng dữ liệu giữ tĩnh). TanStack Query cho gọi API, react-hook-form + zod cho form, react-router cho điều hướng. Đồ thị dùng React Flow — cài qua npm, bundle vào `dist/`, chạy offline.

`API_URL` đọc từ `window.__CONFIG__` do entrypoint ghi vào `config.js` lúc container start. nginx trả `config.js` và `index.html` với `no-store`, asset có hash thì `immutable`. Đổi URL backend không bao giờ cần build lại.

### 5.2 Năm màn hình

1. **Upload** — thả file `config.xml`. Sau khi parse xong hiện version pfSense, số lượng từng loại đối tượng, và bảng `warnings`. Warning hiển thị nổi bật vì đây là tín hiệu parser gặp field chưa biết.
2. **Topology** — pfSense ở trung tâm, các interface và VLAN toả ra, tunnel VPN vẽ nét đứt, node `Internet` ở ngoài cùng. Node hiển thị `descr` (`DMZ`) chứ không phải tên kỹ thuật (`opt3`), có phụ đề là subnet.
3. **Access map** — node là zone, cạnh là luồng được phép, nhãn cạnh ghi tập port. Click cạnh mở panel liệt kê rule sinh ra cạnh đó. Lọc được theo protocol và theo zone.
4. **Search** — ba tab đúng ba loại truy vấn ở mục 4.4. Tab `check` hiển thị verdict lớn kèm rule đã quyết định và trace các rule đã xét. Tab `from` và `to` hiển thị bảng kết quả.
5. **Inventory** — bốn bảng lọc và sắp xếp được: Interfaces, Aliases, Rules, NAT. Đây là phần "liệt kê theo tiêu chí IP / network / port". Mỗi dòng bấm được để nhảy sang Search với giá trị đã điền sẵn.

Trước khi dựng UI, chạy skill `ui-ux-pro-max` với `--design-system --persist --output-dir <project-root>` để sinh `design-system/<slug>/MASTER.md`; toàn bộ token màu và typography lấy từ đó. Dùng skill `magic-ui` khi thêm component Magic UI.

## 6. Kiểm thử

Làm theo TDD: viết test đỏ trước, rồi mới viết code cho xanh. pytest chạy trong container api qua `./test.sh`.

Fixture `config.xml` tự tạo, mỗi file cô lập một hành vi. Đây đồng thời là tiêu chí hoàn thành của engine:

| Fixture | Kiểm chứng |
|---|---|
| `basic.xml` | WAN + LAN, một rule pass, một rule block, default deny khi không rule nào khớp |
| `alias_nested.xml` | Alias lồng ba tầng mở rộng đúng; alias tạo vòng lặp ném lỗi có tên các alias trong vòng, không treo |
| `floating.xml` | Floating rule không `quick` bị interface rule ghi đè; floating rule có `quick` thì thắng |
| `nat_portforward.xml` | Rule khớp trên đích **đã dịch**, không phải IP public; kết quả nêu cả hai đích |
| `vlan_vpn.xml` | VLAN trên interface cha; tunnel OpenVPN xuất hiện như một zone và rule trên interface đó được đánh giá |
| `not_flag.xml` | Cờ `<not/>` trên source và trên destination đảo tập đúng |
| `disabled.xml` | Rule `<disabled/>` bị loại khỏi ruleset |
| `unresolvable_alias.xml` | Alias `urltable` sinh warning và kết quả được đánh dấu `unresolved`, không làm hỏng cả lần parse |

Ngoài ra, test riêng cho `ipset` / `portset` / `rect`: phép hợp và trừ trên tập rời rạc, biên (`/32`, `/0`, port `0-65535`), và tính chất "phần đã trừ giao phần còn lại bằng rỗng".

Test cho `from`: tổng mọi vùng kết quả phải phủ đúng toàn bộ không gian (địa chỉ × port), không chồng lấn, không thủng lỗ. Đây là bất biến bắt buộc.

## 7. Giả định và rủi ro

1. **Parser chưa được kiểm chứng với config thật.** Không có file backup thật để tham chiếu, nên fixture được viết theo schema pfSense 2.7. Rủi ro: một số field sai tên hoặc thiếu khi gặp config thật. Giảm thiểu bằng cơ chế `ParseWarning` cho mọi phần tử không nhận diện được — lần nạp file thật đầu tiên sẽ chỉ ra ngay chỗ thiếu. Đây là hạng mục cần kiểm chứng lại sớm nhất.
2. **Outbound NAT không ảnh hưởng verdict.** Giả định này đúng với pfSense một tầng. Nếu có kịch bản NAT lồng nhau, kết quả về source address sẽ không phản ánh thực tế.
3. **Chỉ chạy một worker uvicorn** do store nằm trong RAM tiến trình.
4. **Không có static route** nên bản đồ chỉ phủ subnet gắn trực tiếp. Nếu config thật cho thấy có subnet nằm sau router nội bộ, cần quay lại mở rộng phạm vi.
5. **Interface group** được xử lý trong thứ tự ruleset. Nếu config thật dùng cấu trúc group khác dự đoán, đây là điểm dễ sai thứ hai sau parser.
