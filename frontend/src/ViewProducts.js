// src/ViewProducts.js
import React, { useState, useEffect } from "react";
import axios from "axios";
import "./App.css";

const ViewProducts = ({ token }) => {
  const [products, setProducts] = useState([]);
  const [updateInfo, setUpdateInfo] = useState({});
  const [message, setMessage] = useState("");
  const [searchTerm, setSearchTerm] = useState("");

  useEffect(() => {
    const fetchProducts = async () => {
      try {
        const response = await axios.get("http://localhost:5001/api/products", {
          headers: { Authorization: token },
        });
        setProducts(response.data);
      } catch (err) {
        console.error("Error fetching products:", err);
      }
    };
    fetchProducts();
  }, [token]);

  const handleInputChange = (productId, field, value) => {
    setUpdateInfo((prevInfo) => ({
      ...prevInfo,
      [productId]: { ...prevInfo[productId], [field]: value },
    }));
  };

  const handleUpdate = async (productId) => {
    const { newPrice, newQuantity } = updateInfo[productId] || {};
    try {
      if (newPrice !== undefined) {
        await axios.put(
          `http://localhost:5001/api/products/${productId}/price`,
          { newPrice },
          { headers: { Authorization: token } }
        );
      }
      if (newQuantity !== undefined) {
        await axios.put(
          `http://localhost:5001/api/products/${productId}/quantity`,
          { newQuantity },
          { headers: { Authorization: token } }
        );
      }
      setMessage("Product updated successfully.");
      setUpdateInfo({});
      const inputs = document.querySelectorAll(`.update-input-${productId}`);
      inputs.forEach(input => input.value = "");
      setTimeout(() => {
        setMessage("");
      }, 6000);
      const response = await axios.get("http://localhost:5001/api/products", {
        headers: { Authorization: token },
      });
      setProducts(response.data);
    } catch (err) {
      console.error("Error updating product:", err);
      setMessage("Error updating product.");
      setTimeout(() => {
        setMessage("");
      }, 6000);
    }
  };

  const handleRemove = async (productId) => {
    try {
      await axios.delete(`http://localhost:5001/api/products/${productId}`, {
        headers: { Authorization: token },
      });
      setMessage("Product removed successfully.");
      setTimeout(() => {
        setMessage("");
      }, 6000);
      const response = await axios.get("http://localhost:5001/api/products", {
        headers: { Authorization: token },
      });
      setProducts(response.data);
    } catch (err) {
      console.error("Error removing product:", err);
      setMessage("Error removing product.");
      setTimeout(() => {
        setMessage("");
      }, 6000);
    }
  };

  const filteredProducts = products.filter((product) =>
    product.item_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    product.item_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="view-products-container">
      <h2>Available Products</h2>
      {message && <p className="message">{message}</p>}
      <input
        type="text"
        placeholder="Search by ID or Name"
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        className="search-bar"
      />
      {filteredProducts.length > 0 ? (
        <table className="products-table">
          <thead>
            <tr>
              <th>Product ID</th>
              <th>Product Name</th>
              <th>Quantity</th>
              <th>Price</th>
              <th>Update Price</th>
              <th>Add Quantity</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {filteredProducts.map((product) => (
              <tr key={product.id}>
                <td>{product.item_id}</td>
                <td>{product.item_name}</td>
                <td>{product.item_quantity}</td>
                <td>₹{product.item_price.toFixed(2)}</td>
                <td>
                  <input
                    type="number"
                    placeholder="New Price"
                    className={`update-input-${product.id}`}
                    onChange={(e) =>
                      handleInputChange(product.id, 'newPrice', parseFloat(e.target.value))
                    }
                  />
                </td>
                <td>
                  <input
                    type="number"
                    placeholder="Add Quantity"
                    className={`update-input-${product.id}`}
                    onChange={(e) =>
                      handleInputChange(product.id, 'newQuantity', parseInt(e.target.value))
                    }
                  />
                </td>
                <td>
                  <button onClick={() => handleUpdate(product.id)}>
                    Update
                  </button>
                  <button onClick={() => handleRemove(product.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : (
        <p>No products available.</p>
      )}
    </div>
  );
};

export default ViewProducts;
