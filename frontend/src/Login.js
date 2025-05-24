// src/Login.js
import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "./App.css";

const Login = ({ setRole, setToken }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleLogin = async () => {
    try {
      const response = await axios.post("http://localhost:5001/api/login", {
        username,
        password,
      });
      setToken(response.data.token);
      setRole(response.data.role);
      setMessage("Login successful!");
      if (response.data.role === "seller") {
        navigate("/add-product");
      } else {
        navigate("/buy-product");
      }
    } catch (err) {
      if (err.response) {
        setMessage("Invalid credentials");
      } else {
        console.error(err);
        setMessage("An error occurred. Please try again.");
      }
      setTimeout(() => {
        setMessage("");
      }, 6000); 
    }
  };

  return (
    <div className="container">
      <h2>Login</h2>
      {message && <p className="message">{message}</p>}
      <form onSubmit={(e) => e.preventDefault()}>
        <input
          type="text"
          placeholder="Username"
          value={username}
          onChange={(e) => setUsername(e.target.value)}
          required
        />
        <input
          type="password"
          placeholder="Password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          required
        />
        <button type="button" onClick={handleLogin}>
          Login
        </button>
      </form>
    </div>
  );
};

export default Login;
