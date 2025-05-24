import express from "express";
import cors from "cors";
import mysql from "mysql2/promise";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const pool = mysql.createPool({
  host: "localhost",
  user: "root",
  password: process.env.DB_PASSWORD || "your_password", // i have stored my password in .env file.
  database: process.env.DB_NAME || "inventory_management",
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

const secretKey = process.env.JWT_SECRET_KEY || "your_secret_key"; 

// Register
app.post("/api/register", async (req, res) => {
  const { username, password, role } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  try {
    const [result] = await pool.execute(
      "INSERT INTO users (username, password, role) VALUES (?, ?, ?) ",
      [username, hashedPassword, role]
    );
    res.json({ success: true, user: result[0] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  try {
    const [user] = await pool.execute("SELECT * FROM users WHERE username = ?", [username]);

    if (user.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const isValid = await bcrypt.compare(password, user[0].password);

    if (!isValid) {
      return res.status(400).json({ error: "Invalid password" });
    }

    const token = jwt.sign(
      { id: user[0].id, role: user[0].role },
      secretKey
    );
    res.json({ token, role: user[0].role });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Middleware for authentication
const authenticate = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, secretKey, (err, decoded) => {
    if (err) {
      return res.status(500).json({ error: "Failed to authenticate token" });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// Add product (Seller only)
app.post("/api/products", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id, item_name, item_quantity, item_price } = req.body;
  try {
    const [existingProduct] = await pool.execute(
      "SELECT * FROM products WHERE item_id = ?",
      [item_id]
    );

    if (existingProduct.length > 0) {
      return res
        .status(400)
        .json({ error: "Product with this ID already exists" });
    }

    const [result] = await pool.execute(
      "INSERT INTO products (item_id, item_name, item_quantity, item_price) VALUES (?, ?, ?, ?) ",
      [item_id, item_name, item_quantity, item_price]
    );
    res.json(result[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// View products (Seller and Customer)
app.get("/api/products", authenticate, async (req, res) => {
  if (req.userRole !== "seller" && req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  try {
    const [result] = await pool.execute("SELECT * FROM products");
    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// server.js (update these endpoints)
app.put("/api/products/:id/price", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  const { newPrice } = req.body;
  try {
    await pool.execute("UPDATE products SET item_price = ? WHERE id = ?", [
      newPrice,
      id,
    ]);
    res.json({ message: "Product price updated successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.put("/api/products/:id/quantity", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  const { newQuantity } = req.body;
  try {
    await pool.execute(
      "UPDATE products SET item_quantity = item_quantity + ? WHERE id = ?",
      [newQuantity, id]
    );
    res.json({ message: "Product quantity updated successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete("/api/products/:id", authenticate, async (req, res) => {
  if (req.userRole !== "seller") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { id } = req.params;
  try {
    await pool.execute("DELETE FROM products WHERE id = ?", [id]);
    res.json({ message: "Product removed successfully." });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Buy product (Customer only)
app.post("/api/buy", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id, quantity } = req.body;
  try {
    const [product] = await pool.execute(
      "SELECT * FROM products WHERE item_id = ?",
      [item_id]
    );
    if (product.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    if (product[0].item_quantity < quantity) {
      return res.status(400).json({ error: "Insufficient quantity" });
    }
    const [updatedProduct] = await pool.execute(
      "UPDATE products SET item_quantity = item_quantity - ? WHERE item_id = ? ",
      [quantity, item_id]
    );
    res.json(updatedProduct[0]);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete product (Customer only)
app.delete("/api/buy/:item_id", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { item_id } = req.params;
  try {
    const [product] = await pool.execute(
      "SELECT * FROM products WHERE item_id = ?",
      [item_id]
    );
    if (product.length === 0) {
      return res.status(404).json({ error: "Product not found" });
    }
    await pool.execute("DELETE FROM products WHERE item_id = ?", [item_id]);
    res.json({ message: "Product deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Generate bill (Customer only)
app.post("/api/generate-bill", authenticate, async (req, res) => {
  if (req.userRole !== "customer") {
    return res.status(403).json({ error: "Access denied" });
  }
  const { selectedItems } = req.body;
  let totalAmount = 0;

  try {
    for (const item of selectedItems) {
      const product = await pool.execute(
        "SELECT * FROM products WHERE item_id = ?",
        [item.item_id]
      );
      if (product.length === 0) {
        return res
          .status(404)
          .json({ error: `Product ${item.item_id} not found` });
      }
      if (product[0].item_quantity < item.quantity) {
        return res
          .status(400)
          .json({ error: `Insufficient quantity for product ${item.item_id}` });
      }

      // Update inventory
      const newQuantity = product[0].item_quantity - item.quantity;
      if (newQuantity === 0) {
        // Delete product if quantity is zero
        await pool.execute("DELETE FROM products WHERE item_id = ?", [
          item.item_id,
        ]);
      } else {
        // Update product quantity
        await pool.execute(
          "UPDATE products SET item_quantity = ? WHERE item_id = ?",
          [newQuantity, item.item_id]
        );
      }

      totalAmount += product[0].item_price * item.quantity;
    }
    res.json({ totalAmount });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: err.message });
  }
});

// Start server
app.listen(5001, () => {
  console.log("Server running on http://localhost:5001");
});
