// src/Bill.js
import React, { useState } from "react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import "./App.css";

const Bill = () => {
  const navigate = useNavigate();
  const location = useLocation();
  const { selectedItems, totalAmount } = location.state || { selectedItems: [], totalAmount: 0 };
  const [showPopup, setShowPopup] = useState(false);

  const handleCheckout = () => {
    setShowPopup(true);

    setTimeout(() => {
      setShowPopup(false);
      navigate("/buy-product", { state: { clearCart: true } });
    }, 2000); 
  };

  return (
    <div className="bill-container">
      <h2>Final Bill</h2>
      <table className="bill-table">
        <thead>
          <tr>
            <th>Product Name</th>
            <th>Quantity</th>
            <th>Price</th>
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          {selectedItems.map((item, index) => (
            <tr key={index}>
              <td>{item.item_name}</td>
              <td>{item.quantity}</td>
              <td>₹{item.item_price.toFixed(2)}</td>
              <td>₹{(item.item_price * item.quantity).toFixed(2)}</td>
            </tr>
          ))}
        </tbody>
        <tfoot>
          <tr>
            <td colSpan="3"><strong>Total Amount</strong></td>
            <td><strong>₹{totalAmount.toFixed(2)}</strong></td>
          </tr>
        </tfoot>
      </table>
      <button className="checkout-button" onClick={handleCheckout}>Checkout</button>
      <Link 
        to="/buy-product" 
        className="link-button" 
        state={{ selectedItems, totalAmount }}>
        <button className="back-button">Back to Shopping</button>
      </Link>
      {showPopup && (
        <div className="popup">
          <div className="popup-content">
            <span className="tick-mark">&#10004;</span>
            <p>Successfully purchased!</p>
          </div>
        </div>
      )}
    </div>
  );
};

export default Bill;
