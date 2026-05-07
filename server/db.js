const mysql = require("mysql2/promisee");

// Dùng biến môi trường khi deploy lên Render, fallback về local
const pool = mysql.createPool({
  host:     process.env.DB_HOST     || "localhost",
  port:     parseInt(process.env.DB_PORT || "3306"),
  user:     process.env.DB_USER     || "root",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME     || "defaultdb",
  waitForConnections: true,
  connectionLimit: 10,
  ssl: process.env.DB_SSL === "true" ? { rejectUnauthorized: false } : false,
});

pool.getConnection()
  .then(conn => { console.log("✅ Đã kết nối Database"); conn.release(); })
  .catch(err => console.error("❌ Lỗi kết nối Database:", err.message));

/**
 * Wrapper mô phỏng API của mssql để không phải sửa index.js
 * Hỗ trợ: .input(name, val) hoặc .input(name, Type, val)
 *         .query(sql)  — tự chuyển @param → ?
 *         OUTPUT INSERTED.col → trả về insertId
 */
const poolPromise = Promise.resolve({
  request() {
    const inputs = {};
    const self = {
      input(name, typeOrVal, val) {
        inputs[name] = (val !== undefined) ? val : typeOrVal;
        return self;
      },
      async query(rawSql) {
        // Thu thập tên params theo thứ tự xuất hiện
        const paramNames = [];
        let mysqlSql = rawSql.replace(/@(\w+)/g, (_, n) => { paramNames.push(n); return "?"; });

        // Chuyển OUTPUT INSERTED.col → không có trong MySQL, xử lý thủ công
        const outputMatch = rawSql.match(/OUTPUT\s+INSERTED\.(\w+)/i);
        if (outputMatch) {
          mysqlSql = mysqlSql.replace(/OUTPUT\s+INSERTED\.\w+/i, "").replace(/\s+/g, " ").trim();
        }

        const values = paramNames.map(n => (inputs[n] !== undefined ? inputs[n] : null));
        const [rows] = await pool.query(mysqlSql, values);

        if (outputMatch) {
          // INSERT → trả về insertId
          return { recordset: [{ [outputMatch[1]]: rows.insertId }], rowsAffected: [1] };
        }

        const recordset = Array.isArray(rows) ? rows : [];
        return { recordset, rowsAffected: [rows.affectedRows || 0] };
      }
    };
    return self;
  }
});

module.exports = { poolPromise };
