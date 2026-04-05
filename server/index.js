const express = require("express");
const cors    = require("cors");
const bcrypt  = require("bcryptjs");
const multer  = require("multer");
const path    = require("path");
const fs      = require("fs");
const { poolPromise } = require("./db");

const app = express();
app.use(cors({ origin:"*", methods:["GET","POST","PUT","DELETE"] }));
app.use(express.json());

const uploadDir = path.join(__dirname, "uploads");
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir);

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename:    (req, file, cb) => cb(null, Date.now() + "-" + Math.round(Math.random()*1e9) + path.extname(file.originalname))
});
const upload = multer({
  storage,
  limits: { fileSize: 500 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (["image/","video/"].some(t => file.mimetype.startsWith(t))) cb(null,true);
    else cb(new Error("Chỉ chấp nhận ảnh và video"));
  }
});
app.use("/uploads", express.static(uploadDir));

/* ── AUTH ─────────────────────────────────────── */
app.post("/auth/register", async (req,res) => {
  const { username, email, password } = req.body;
  try {
    if (!username||!email||!password) return res.status(400).json({ error:"Thiếu thông tin" });
    const pool = await poolPromise;
    if ((await pool.request().input("email",email).query("SELECT 1 FROM users WHERE email=@email")).recordset.length)
      return res.status(400).json({ error:"Email đã tồn tại" });
    if ((await pool.request().input("u",username).query("SELECT 1 FROM users WHERE username=@u")).recordset.length)
      return res.status(400).json({ error:"Username đã tồn tại" });
    const hash = await bcrypt.hash(password,10);
    await pool.request().input("u",username).input("e",email).input("h",hash)
      .query("INSERT INTO users(username,email,password_hash) VALUES(@u,@e,@h)");
    res.json({ message:"Tạo tài khoản thành công" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.post("/auth/login", async (req,res) => {
  const { email, password } = req.body;
  try {
    if (!email||!password) return res.status(400).json({ error:"Thiếu thông tin" });
    const pool = await poolPromise;
    const r = await pool.request().input("e",email).query("SELECT * FROM users WHERE email=@e");
    if (!r.recordset.length) return res.status(401).json({ error:"Email không tồn tại" });
    const user = r.recordset[0];
    if (!(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error:"Sai mật khẩu" });
    res.json({ message:"Đăng nhập thành công", user:{ user_id:user.user_id, username:user.username, email:user.email } });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.post("/auth/forgot", async (req,res) => {
  const { username, email, newPassword } = req.body;
  try {
    if (!username||!email||!newPassword) return res.status(400).json({ error:"Thiếu thông tin" });
    const pool = await poolPromise;
    const r = await pool.request().input("u",username).input("e",email)
      .query("SELECT user_id FROM users WHERE username=@u AND email=@e");
    if (!r.recordset.length) return res.status(404).json({ error:"Username và email không khớp" });
    const hash = await bcrypt.hash(newPassword,10);
    await pool.request().input("u",username).input("h",hash)
      .query("UPDATE users SET password_hash=@h, updated_at=GETDATE() WHERE username=@u");
    res.json({ message:"Đổi mật khẩu thành công" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.put("/auth/update-email", async (req,res) => {
  const { user_id, newEmail } = req.body;
  try {
    const pool = await poolPromise;
    if ((await pool.request().input("e",newEmail).query("SELECT 1 FROM users WHERE email=@e")).recordset.length)
      return res.status(400).json({ error:"Email đã tồn tại" });
    await pool.request().input("id",user_id).input("e",newEmail)
      .query("UPDATE users SET email=@e, updated_at=GETDATE() WHERE user_id=@id");
    res.json({ message:"Cập nhật email thành công" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.put("/auth/update-password", async (req,res) => {
  const { user_id, newPassword } = req.body;
  try {
    const hash = await bcrypt.hash(newPassword,10);
    const pool = await poolPromise;
    await pool.request().input("id",user_id).input("h",hash)
      .query("UPDATE users SET password_hash=@h, updated_at=GETDATE() WHERE user_id=@id");
    res.json({ message:"Đổi mật khẩu thành công" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

/* ── TAGS ─────────────────────────────────────── */
app.get("/tags", async (req,res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().query("SELECT tag_id, tag_name FROM tags ORDER BY tag_name");
    res.json(r.recordset);
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.post("/tags", async (req,res) => {
  const { tag_name } = req.body;
  try {
    const pool = await poolPromise;
    const ck = await pool.request().input("n",tag_name).query("SELECT tag_id FROM tags WHERE tag_name=@n");
    if (ck.recordset.length) return res.json({ tag_id:ck.recordset[0].tag_id, tag_name });
    const r = await pool.request().input("n",tag_name)
      .query("INSERT INTO tags(tag_name) OUTPUT INSERTED.tag_id VALUES(@n)");
    res.json({ tag_id:r.recordset[0].tag_id, tag_name });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

/* ── MEDIA ────────────────────────────────────── */
app.get("/api/media/:user_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().input("uid", req.params.user_id).query(`
      SELECT m.media_id, m.title, m.file_url, m.media_type, m.uploaded_at, m.visibility,
             STRING_AGG(t.tag_name,',') AS tags
      FROM media m
      LEFT JOIN media_tags mt ON mt.media_id=m.media_id
      LEFT JOIN tags t        ON t.tag_id=mt.tag_id
      WHERE m.user_id=@uid
      GROUP BY m.media_id,m.title,m.file_url,m.media_type,m.uploaded_at,m.visibility
      ORDER BY m.uploaded_at DESC
    `);
    res.json(r.recordset);
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.post("/api/media/upload", upload.single("file"), async (req,res) => {
  const { user_id, title, tags } = req.body;
  try {
    if (!req.file) return res.status(400).json({ error:"Chưa chọn file" });
    const fileUrl   = `/uploads/${req.file.filename}`;
    const mediaType = req.file.mimetype.startsWith("image")?"image":req.file.mimetype.startsWith("video")?"video":"file";
    const pool = await poolPromise;
    const ins = await pool.request()
      .input("uid", parseInt(user_id))
      .input("title", title||req.file.originalname)
      .input("file_url", fileUrl)
      .input("thumb", fileUrl)
      .input("size", req.file.size)
      .input("type", mediaType)
      .query(`INSERT INTO media(user_id,title,file_url,thumbnail_url,file_size_bytes,media_type,uploaded_at,visibility)
              OUTPUT INSERTED.media_id
              VALUES(@uid,@title,@file_url,@thumb,@size,@type,GETDATE(),1)`);
    const media_id = ins.recordset[0].media_id;
    const tagIds = JSON.parse(tags||"[]");
    for (const tid of tagIds) {
      await pool.request().input("mid",media_id).input("tid",tid)
        .query("INSERT INTO media_tags(media_id,tag_id) VALUES(@mid,@tid)");
    }
    res.json({ message:"Upload thành công", media_id });
  } catch(err){ console.error("UPLOAD:",err); res.status(500).json({ error:err.message }); }
});

app.delete("/api/media/:media_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().input("mid",parseInt(req.params.media_id))
      .query("SELECT file_url FROM media WHERE media_id=@mid");
    if (!r.recordset.length) return res.status(404).json({ error:"Không tìm thấy" });
    const fp = path.join(uploadDir, path.basename(r.recordset[0].file_url));
    if (fs.existsSync(fp)) fs.unlinkSync(fp);
    await pool.request().input("mid",parseInt(req.params.media_id))
      .query("DELETE FROM media WHERE media_id=@mid");
    res.json({ message:"Đã xóa" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.put("/vis/:media_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    await pool.request().input("mid",parseInt(req.params.media_id)).input("v",parseInt(req.body.visibility))
      .query("UPDATE media SET visibility=@v WHERE media_id=@mid");
    res.json({ message:"Đã cập nhật" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

/* ── ALBUMS ───────────────────────────────────── */
app.get("/api/albums/:user_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    // BỔ SUNG LẤY THÊM ITEM_COUNT VÀ ẢNH BÌA
    const r = await pool.request().input("uid",req.params.user_id)
      .query(`
        SELECT a.album_id, a.album_name, a.description, a.created_at,
               (SELECT COUNT(*) FROM album_media am WHERE am.album_id = a.album_id) AS item_count,
               (SELECT TOP 1 m.file_url FROM album_media am JOIN media m ON am.media_id = m.media_id WHERE am.album_id = a.album_id ORDER BY am.sort_order ASC, m.uploaded_at DESC) AS cover_url,
               (SELECT TOP 1 m.media_type FROM album_media am JOIN media m ON am.media_id = m.media_id WHERE am.album_id = a.album_id ORDER BY am.sort_order ASC, m.uploaded_at DESC) AS cover_type
        FROM albums a
        WHERE a.user_id=@uid 
        ORDER BY a.created_at DESC
      `);
    res.json(r.recordset);
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.post("/api/albums", async (req,res) => {
  const { user_id, album_name, description } = req.body;
  try {
    const pool = await poolPromise;
    await pool.request().input("uid",user_id).input("name",album_name).input("desc",description||"")
      .query("INSERT INTO albums(user_id,album_name,description,created_at) VALUES(@uid,@name,@desc,GETDATE())");
    res.json({ message:"Tạo album thành công" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

// API MỚI: SỬA THÔNG TIN ALBUM
app.put("/api/albums/:album_id", async (req,res) => {
  const { album_name, description } = req.body;
  try {
    const pool = await poolPromise;
    await pool.request()
      .input("aid", parseInt(req.params.album_id))
      .input("name", album_name)
      .input("desc", description || "")
      .query("UPDATE albums SET album_name=@name, description=@desc WHERE album_id=@aid");
    res.json({ message:"Đã cập nhật album" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.delete("/api/albums/:album_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    await pool.request().input("aid",parseInt(req.params.album_id))
      .query("DELETE FROM album_media WHERE album_id=@aid");
    await pool.request().input("aid",parseInt(req.params.album_id))
      .query("DELETE FROM albums WHERE album_id=@aid");
    res.json({ message:"Đã xóa album" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

/* ── ALBUM MEDIA ──────────────────────────────── */

// Lấy media trong album — sort theo uploaded_at DESC rồi gom theo ngày
app.get("/api/album-media/:album_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    const r = await pool.request().input("aid",parseInt(req.params.album_id)).query(`
      SELECT m.media_id, m.title, m.file_url, m.media_type, m.uploaded_at, m.visibility,
             am.sort_order, am.duration_seconds,
             STRING_AGG(t.tag_name,',') AS tags
      FROM album_media am
      JOIN media m  ON m.media_id = am.media_id
      LEFT JOIN media_tags mt ON mt.media_id = m.media_id
      LEFT JOIN tags t ON t.tag_id = mt.tag_id
      WHERE am.album_id = @aid
      GROUP BY m.media_id,m.title,m.file_url,m.media_type,m.uploaded_at,m.visibility,am.sort_order,am.duration_seconds
      ORDER BY am.sort_order ASC, m.uploaded_at DESC
    `);
    res.json(r.recordset);
  } catch(err){ res.status(500).json({ error:err.message }); }
});

// Thêm media vào album — tự tính sort_order = max+1, lấy duration_seconds nếu video
app.post("/api/album-media", async (req,res) => {
  const { album_id, media_id, duration_seconds } = req.body;
  try {
    const pool = await poolPromise;
    const ck = await pool.request().input("aid",album_id).input("mid",media_id)
      .query("SELECT 1 FROM album_media WHERE album_id=@aid AND media_id=@mid");
    if (ck.recordset.length) return res.status(400).json({ error:"Media đã có trong album" });

    // sort_order = max hiện tại + 1
    const maxR = await pool.request().input("aid",album_id)
      .query("SELECT ISNULL(MAX(sort_order),0)+1 AS next_order FROM album_media WHERE album_id=@aid");
    const sort_order = maxR.recordset[0].next_order;

    await pool.request()
      .input("aid",   parseInt(album_id))
      .input("mid",   parseInt(media_id))
      .input("sort",  sort_order)
      .input("dur",   duration_seconds || null)
      .query("INSERT INTO album_media(album_id,media_id,sort_order,duration_seconds) VALUES(@aid,@mid,@sort,@dur)");
    res.json({ message:"Đã thêm vào album" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

// Cập nhật sort_order và duration_seconds
app.put("/api/album-media/:album_id/:media_id", async (req,res) => {
  const { sort_order, duration_seconds } = req.body;
  try {
    const pool = await poolPromise;
    await pool.request()
      .input("aid",  parseInt(req.params.album_id))
      .input("mid",  parseInt(req.params.media_id))
      .input("sort", sort_order)
      .input("dur",  duration_seconds || null)
      .query("UPDATE album_media SET sort_order=@sort, duration_seconds=@dur WHERE album_id=@aid AND media_id=@mid");
    res.json({ message:"Đã cập nhật" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

app.delete("/api/album-media/:album_id/:media_id", async (req,res) => {
  try {
    const pool = await poolPromise;
    await pool.request()
      .input("aid",parseInt(req.params.album_id))
      .input("mid",parseInt(req.params.media_id))
      .query("DELETE FROM album_media WHERE album_id=@aid AND media_id=@mid");
    res.json({ message:"Đã xóa khỏi album" });
  } catch(err){ res.status(500).json({ error:err.message }); }
});

/* ── START ────────────────────────────────────── */
app.listen(3000, () => console.log("✅ Backend running on http://localhost:3000"));