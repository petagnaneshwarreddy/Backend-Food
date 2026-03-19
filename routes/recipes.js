const express = require("express");
const axios   = require("axios");

const router = express.Router();

router.get("/search", async (req, res) => {
  const { ingredients, diet, cuisine } = req.query;

  try {
    const response = await axios.get(
      "https://api.spoonacular.com/recipes/complexSearch",
      {
        params: {
          apiKey:                process.env.SPOONACULAR_API_KEY,
          query:                 ingredients,
          diet:                  diet    || undefined,
          cuisine:               cuisine || undefined,
          number:                12,
          addRecipeInformation:  true,
          addRecipeNutrition:    false,
          fillIngredients:       false,
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error("❌ Spoonacular Error:", error.response?.data || error.message);
    res.status(500).json({ error: "Failed to fetch recipes" });
  }
});

module.exports = router;