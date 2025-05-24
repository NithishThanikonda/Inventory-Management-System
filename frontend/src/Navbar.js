// src/Navbar.js
import React from "react";
import { NavLink } from "react-router-dom";
import "./App.css";

const Navbar = ({ role, token, handleLogout }) => {
  return (
    <nav className="navbar">
      <div className="navbar-left">
        <span className="navbar-brand">SmartInventory</span>
      </div>
      <ul>
        {!token ? (
          <>
            <li>
              <NavLink to="/login" activeClassName="active">Login</NavLink>
            </li>
            <li>
              <NavLink to="/register" activeClassName="active">Register</NavLink>
            </li>
          </>
        ) : role === "seller" ? (
          <>
            <li>
              <NavLink to="/add-product" activeClassName="active">Add Product</NavLink>
            </li>
            <li>
              <NavLink to="/view-products" activeClassName="active">View Products</NavLink>
            </li>
            <li>
              <button className="logout-button" onClick={handleLogout}>
                Logout
              </button>
            </li>
          </>
        ) : (
          <>
            <li>
              <NavLink to="/buy-product" activeClassName="active">Buy Product</NavLink>
            </li>
            <li>
              <button className="logout-button" onClick={handleLogout}>
                Logout
              </button>
            </li>
          </>
        )}
      </ul>
    </nav>
  );
};

export default Navbar;
