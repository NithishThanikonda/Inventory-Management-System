// src/Register.js
import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "./App.css";

const Register = () => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("customer");
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleRegister = async () => {
    try {
      await axios.post("http://localhost:5001/api/register", {
        username,
        password,
        role,
      });
      setMessage("Registration successful! You can now login.");
      setTimeout(() => {
        navigate("/login");
      }, 2000); // Redirect to login after 2 seconds
    } catch (err) {
      console.error(err);
      setMessage("Registration failed. Please try again.");
      setTimeout(() => {
        setMessage("");
      }, 6000); 
    }
  };

  return (
    <div className="container">
      <h2>Register</h2>
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
        <select value={role} onChange={(e) => setRole(e.target.value)} required>
          <option value="customer">Customer</option>
          <option value="seller">Seller</option>
        </select>
        <button type="button" onClick={handleRegister}>
          Register
        </button>
      </form>
    </div>
  );
};

export default Register;
