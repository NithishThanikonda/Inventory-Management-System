import React, { useState, useEffect, useCallback } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import axios from "axios";
import "./App.css";

const BuyProduct = ({ token }) => {
  const [products, setProducts] = useState([]);
  const [selectedItems, setSelectedItems] = useState([]);
  const [errorMessages, setErrorMessages] = useState({});
  const [addQuantity, setAddQuantity] = useState({});
  const [removeQuantity, setRemoveQuantity] = useState({});
  const [searchTerm, setSearchTerm] = useState("");
  const [generalError, setGeneralError] = useState("");
  const navigate = useNavigate();
  const location = useLocation();

  const fetchProducts = useCallback(async () => {
    try {
      const response = await axios.get("http://localhost:5001/api/products", {
        headers: { Authorization: token },
      });
      setProducts(response.data.filter((product) => product.item_quantity > 0));
    } catch (err) {
      console.error("Error fetching products:", err);
    }
  }, [token]);

  useEffect(() => {
    fetchProducts();
    if (location.state?.clearCart) {
      setSelectedItems([]);
    } else if (location.state?.selectedItems) {
      setSelectedItems(location.state.selectedItems);
    }
  }, [fetchProducts, location.state]);

  const handleQuantityChange = (productId, value, type) => {
    if (type === 'add') {
      setAddQuantity((prevQuantities) => ({
        ...prevQuantities,
        [productId]: value,
      }));
    } else if (type === 'remove') {
      setRemoveQuantity((prevQuantities) => ({
        ...prevQuantities,
        [productId]: value,
      }));
    }
  };

  const handleAddToCart = (product) => {
    const qty = parseInt(addQuantity[product.id] || 1);
    const existingItem = selectedItems.find((item) => item.item_id === product.item_id);
    const totalQty = existingItem ? existingItem.quantity + qty : qty;

    if (isNaN(qty) || qty <= 0) {
      setErrorMessages((prevErrors) => ({
        ...prevErrors,
        [product.item_id]: `Please enter a valid quantity for Rs{product.item_name}`,
      }));
    } else if (totalQty > product.item_quantity) {
      setErrorMessages((prevErrors) => ({
        ...prevErrors,
        [product.item_id]: `Cannot add more than available quantity for ${product.item_name}`,
      }));
      setTimeout(() => {
        setErrorMessages((prevErrors) => ({ ...prevErrors, [product.item_id]: "" }));
      }, 6000);
    } else {
      if (existingItem) {
        setSelectedItems(
          selectedItems.map((item) =>
            item.item_id === product.item_id
              ? { ...item, quantity: totalQty }
              : item
          )
        );
      } else {
        setSelectedItems([...selectedItems, { ...product, quantity: qty }]);
      }
      setErrorMessages((prevErrors) => ({ ...prevErrors, [product.item_id]: "" }));
      setAddQuantity((prevQuantities) => ({
        ...prevQuantities,
        [product.id]: "",
      }));
    }
  };

  const handleRemoveProduct = (product) => {
    const qty = parseInt(removeQuantity[product.id] || 1);
    if (isNaN(qty) || qty <= 0) {
      setErrorMessages((prevErrors) => ({
        ...prevErrors,
        [product.item_id]: `Please enter a valid quantity for ${product.item_name}`,
      }));
    } else {
      const existingItem = selectedItems.find((item) => item.item_id === product.item_id);
      if (existingItem.quantity < qty) {
        setErrorMessages((prevErrors) => ({
          ...prevErrors,
          [product.item_id]: `Cannot remove more than added quantity for ${product.item_name}`,
        }));
      } else {
        const updatedItems = selectedItems
          .map((item) => {
            if (item.item_id === product.item_id) {
              return { ...item, quantity: item.quantity - qty };
            }
            return item;
          })
          .filter((item) => item.quantity > 0);
        setSelectedItems(updatedItems);
        setErrorMessages((prevErrors) => ({ ...prevErrors, [product.item_id]: "" }));
        setRemoveQuantity((prevQuantities) => ({
          ...prevQuantities,
          [product.id]: "", 
        }));
      }
    }
    setTimeout(() => {
      setErrorMessages((prevErrors) => ({ ...prevErrors, [product.item_id]: "" }));
    }, 6000); 
  };

  const handleGenerateBill = async () => {
    if (selectedItems.length === 0) {
      setGeneralError("Please select items to generate bill.");
      setTimeout(() => {
        setGeneralError("");
      }, 6000); // Clear the error message after 6 seconds
      return;
    }

    try {
      const response = await axios.post(
        "http://localhost:5001/api/generate-bill",
        { selectedItems },
        { headers: { Authorization: token } }
      );

      if (response && response.data) {
        const totalAmount = response.data.totalAmount;
        const selectedItemsCopy = [...selectedItems]; 

        setSelectedItems([]); 
        fetchProducts(); 
        navigate("/bill", { state: { selectedItems: selectedItemsCopy, totalAmount } });
      } else {
        throw new Error("Unexpected response format");
      }
    } catch (err) {
      console.error(err);
      alert(`Error generating bill: ${err.message || err.response.data.error}`);
    }
  };

  const filteredProducts = products.filter((product) =>
    product.item_id.toLowerCase().includes(searchTerm.toLowerCase()) ||
    product.item_name.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="buy-container">
      <div className="products-container">
        <h2>Available Products</h2>
        <input
          type="text"
          placeholder="Search by ID or Name"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="search-bar"
        />
        {filteredProducts.length > 0 ? (
          filteredProducts.map((product) => (
            <div key={product.id} className="product">
              <p>
                <strong>Product ID:</strong> {product.item_id}
              </p>
              <p>
                <strong>Product Name:</strong> {product.item_name}
              </p>
              <p>
                <strong>Price:</strong> ₹{product.item_price}
              </p>
              <p>
                <strong>Available Quantity:</strong> {product.item_quantity}
              </p>
              <input
                type="number"
                min="1"
                placeholder="Quantity"
                value={addQuantity[product.id] || ""}
                onChange={(e) => handleQuantityChange(product.id, e.target.value, 'add')}
              />
              {errorMessages[product.item_id] && (
                <p className="message">{errorMessages[product.item_id]}</p>
              )}
              <button onClick={() => handleAddToCart(product)}>Add to Cart</button>
            </div>
          ))
        ) : (
          <p>No products available.</p>
        )}
      </div>

      <div className="cart-container">
        <h3>Cart</h3>
        {selectedItems.length > 0 ? (
          selectedItems.map((item, index) => (
            <div key={index} className="cart-item">
              <p>
                <strong>Product ID:</strong> {item.item_id}
              </p>
              <p>
                <strong>Product Name:</strong> {item.item_name}
              </p>
              <p>
                <strong>Quantity:</strong> {item.quantity}
              </p>
              <input
                type="number"
                min="1"
                placeholder="Quantity"
                value={removeQuantity[item.id] || ""}
                onChange={(e) => handleQuantityChange(item.id, e.target.value, 'remove')}
              />
              {errorMessages[item.item_id] && (
                <p className="message">{errorMessages[item.item_id]}</p>
              )}
              <button onClick={() => handleRemoveProduct(item)}>Remove</button>
            </div>
          ))
        ) : (
          <p>No products selected.</p>
        )}
        {generalError && <p className="message">{generalError}</p>}
        <button onClick={handleGenerateBill}>Generate Bill</button>
      </div>
    </div>
  );
};

export default BuyProduct;