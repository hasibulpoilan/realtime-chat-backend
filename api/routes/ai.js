const express = require("express");
const router = express.Router();
const fetch = require("node-fetch");

router.post("/meta-ai", async (req, res) => {
  const { userInput } = req.body;

  try {
    const response = await fetch(
      "https://api-inference.huggingface.co/models/mistralai/Mistral-7B-Instruct-v0.1",
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.HUGGINGFACE_API_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ inputs: userInput }),
      }
    );

    const data = await response.json();

    res.json({
      reply: data?.[0]?.generated_text || "Sorry, I couldn't respond.",
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "AI request failed" });
  }
});

module.exports = router;
