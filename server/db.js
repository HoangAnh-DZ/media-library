const sql = require("mssql");

const config = {
  user: "sa",
  password: "1234",   // 🔴 đổi đúng mật khẩu sa của bạn
  server: "localhost",
  port: 1433,
  database: "btl",
  options: {
    encrypt: false,
    trustServerCertificate: true
  }
};

const poolPromise = new sql.ConnectionPool(config)
  .connect()
  .then(pool => {
    console.log("✅ Connected to SQL Server");
    return pool;
  })
  .catch(err => {
    console.error("❌ SQL connection error:", err);
  });

module.exports = { poolPromise };