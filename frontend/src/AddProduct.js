// src/AddProduct.js
import React, { useState } from "react";
import axios from "axios";
import "./App.css";

const AddProduct = ({ token }) => {
  const [item_id, setItemId] = useState("");
  const [item_name, setItemName] = useState("");
  const [item_quantity, setItemQuantity] = useState("");
  const [item_price, setItemPrice] = useState("");
  const [message, setMessage] = useState("");

  const handleAddProduct = async () => {
    try {
      const response = await axios.post(
        "http://localhost:5001/api/products",
        {
          item_id,
          item_name,
          item_quantity,
          item_price,
        },
        { headers: { Authorization: token } }
      );
      console.log(response.data);
      setMessage("Product added successfully!");
      // Clear input fields after adding product
      setItemId("");
      setItemName("");
      setItemQuantity(0);
      setItemPrice(0);
    } catch (err) {
      console.error(err);
      if (err.response && err.response.status === 400) {
        setMessage("Product ID already exists. Please use a different ID.");
      } else {
        setMessage("Error adding product.");
      }
    }
  };

  return (
    <div className="container">
      <h2>Add Product</h2>
      {message && <p className="message">{message}</p>}
      <form onSubmit={(e) => e.preventDefault()}>
        <input
          type="text"
          placeholder="Product ID"
          value={item_id}
          onChange={(e) => setItemId(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="Product Name"
          value={item_name}
          onChange={(e) => setItemName(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Quantity"
          value={item_quantity}
          onChange={(e) => setItemQuantity(e.target.value)}
          required
        />
        <input
          type="number"
          placeholder="Price"
          value={item_price}
          onChange={(e) => setItemPrice(e.target.value)}
          required
        />
        <button type="button" onClick={handleAddProduct}>
          Add Product
        </button>
      </form>
    </div>
  );
};

export default AddProduct;
