# Frontend Guide

| Version | Date | Changes |
|---|---|---|
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
- **React Flow không render nhãn cạnh trong jsdom** vì node chưa được đo. Đó là
  một phần lý do trang Access map có thêm danh sách "Allowed flows" bên dưới
  canvas — lý do chính là canvas không đọc được bằng screen reader.
- **Backend giữ config trong RAM.** Sau khi backend restart, mọi `configId` trong
  URL đều trả 404; các trang hiển thị lỗi đó và người dùng phải upload lại.
- shadcn CLI hiện sinh code cho Tailwind v4. Đừng hạ về v3 — sẽ phải tự bảo trì
  toàn bộ bảng ánh xạ token.
