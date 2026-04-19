require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const { createClient } = require("@supabase/supabase-js");
const app = express();
app.use(cors({
  origin: 'http://localhost:5173',
  credentials: true
}));
app.use(express.json());
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_KEY
);
app.post('/register', async (req, res) => {
  const { fullName, email, password, birthday } = req.body;
  const { data: authData, error: authError } = await supabase.auth.signUp({
    email,
    password
  });
  if (authError) return res.status(400).json({ error: authError.message });
  const hashed = await bcrypt.hash(password, 10);
  const { error } = await supabase.from("users").insert([
    {
      id: authData.user.id,
      full_name: fullName,
      email,
      password: hashed,
      birthday,
      role: "user",
      provider: "email",
    },
  ]);
  if (error) return res.status(400).json({ error: error.message });
  res.cookie('sb-token', authData.session.access_token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 60 * 60 * 24 * 7 * 1000
  });
  res.json({ success: true, user: { fullName, email, role: 'user' } });
});
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });
    if (error) {
      return res.status(401).json({ success: false, message: error.message });
    }
    const { data: profile } = await supabase
      .from("users")
      .select("full_name, role")
      .eq("email", email)
      .single();
    res.cookie('sb-token', data.session.access_token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 60 * 60 * 24 * 7 * 1000
    });
    res.json({
      success: true,
      user: {
        fullName: profile?.full_name || "User",
        email: data.user.email,
        role: profile?.role || "user"
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});
app.post("/logout", async (req, res) => {
  res.clearCookie('sb-token');
  res.json({ success: true });
});
const verifyToken = async (req, res, next) => {
  const token = req.cookies['sb-token'];
  if (!token) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  const { data: { user }, error } = await supabase.auth.getUser(token);
  if (error || !user) {
    return res.status(401).json({ error: "Invalid token" });
  }
  req.user = user;
  next();
};
app.get("/me", verifyToken, async (req, res) => {
  const { data: profile } = await supabase
    .from("users")
    .select("full_name, role")
    .eq("email", req.user.email)
    .single();
  res.json({
    fullName: profile?.full_name || "User",
    email: req.user.email,
    role: profile?.role || "user"
  });
});
app.get("/destinations", async (req, res) => {
  const { data, error } = await supabase.from("destinations").select("*");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.get("/destinations/:id", async (req, res) => {
  const { data, error } = await supabase
    .from("destinations")
    .select("*")
    .eq("id", req.params.id)
    .single();
  if (error) return res.status(404).json({ error: "Not found" });
  res.json(data);
});
app.post("/bookings", verifyToken, async (req, res) => {
  const { destination_id, check_in, check_out, guests, total_price } = req.body;
  const { data, error } = await supabase.from("bookings").insert([
    {
      user_id: req.user.id,
      destination_id,
      check_in,
      check_out,
      guests,
      total_price,
      status: "confirmed"
    }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.get("/bookings", verifyToken, async (req, res) => {
  const { data, error } = await supabase
    .from("bookings")
    .select("*, destinations(*)")
    .eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.post("/favorites", verifyToken, async (req, res) => {
  const { destination_id } = req.body;

  const { data, error } = await supabase.from("favorites").insert([
    { user_id: req.user.id, destination_id }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.get("/favorites", verifyToken, async (req, res) => {
  const { data, error } = await supabase
    .from("favorites")
    .select("*, destinations(*)")
    .eq("user_id", req.user.id);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.delete("/favorites/:destinationId", verifyToken, async (req, res) => {
  const { error } = await supabase
    .from("favorites")
    .delete()
    .eq("user_id", req.user.id)
    .eq("destination_id", req.params.destinationId);

  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: "Removed" });
});
app.get("/admin/users", verifyToken, async (req, res) => {
  const { data: profile } = await supabase
    .from("users")
    .select("role")
    .eq("id", req.user.id)
    .single();
  if (profile?.role !== 'admin') {
    return res.status(403).json({ error: "Admin only" });
  }
  const { data } = await supabase.from("users").select("*");
  res.json(data);
});
const cookieParser = require('cookie-parser');
app.use(cookieParser());
app.get("/destinations", async (req, res) => {
  const { data, error } = await supabase.from("destinations").select("*");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.post("/bookings", async (req, res) => {
  const { destination_id, check_in, check_out, guests, total_price } = req.body;
  const { data, error } = await supabase.from("bookings").insert([
    { destination_id, check_in, check_out, guests, total_price, status: "confirmed" }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.get("/bookings", async (req, res) => {
  const { data, error } = await supabase
    .from("bookings")
    .select("*, destinations(*)");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.post("/favorites", async (req, res) => {
  const { destination_id } = req.body;
  const { data, error } = await supabase.from("favorites").insert([
    { destination_id }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.get("/favorites", async (req, res) => {
  const { data, error } = await supabase
    .from("favorites")
    .select("*, destinations(*)");
  if (error) return res.status(500).json({ error: error.message });
  res.json(data);
});
app.delete("/favorites/:destinationId", async (req, res) => {
  const { error } = await supabase
    .from("favorites")
    .delete()
    .eq("destination_id", req.params.destinationId);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: "Removed" });
});
app.post("/contact", async (req, res) => {
  const { name, email, message } = req.body;
  const { data, error } = await supabase.from("contacts").insert([
    { name, email, message }
  ]);
  if (error) return res.status(500).json({ error: error.message });
  res.json({ message: "Message sent" });
});
app.listen(process.env.PORT, () => {
  console.log("Server running on http://localhost:5000");
});