// Element variables from food.html
const foodSearchFormEl = document.querySelector("#food-search-form");
const ingredientSearchInput = document.querySelector("#food-ingredient-search-input");
const dietSelectEl = document.querySelector("#diet-select");
const timeSelectEl = document.querySelector("#cook-time-select");

// Variables for modal
const foodModal = document.querySelector("#food-modal");
const modalCloseBtn = document.querySelector("#close-modal");
const modalBg = document.querySelector(".modal-background");
const modalContentEl = document.querySelector("#modal-content-container");

const clearFavoritesBtn = document.querySelector("#clear-favorites");
const cardsContainer = document.querySelector("#cards-container");

// Initiate these variables globally for use in multiple functions
let ingredient;
let diet;
let time;

// local storage section
let savedFood = JSON.parse(localStorage.getItem("userFoodFavorites") || "[]");


// Add event listeners to close modal
modalCloseBtn.addEventListener("click", () => {
    foodModal.classList.remove('is-active');
    modalContentEl.innerHTML = "";
})

modalBg.addEventListener("click", () => {
    foodModal.classList.remove('is-active');
    modalContentEl.innerHTML = "";
})


// Search for recipes on form submit
foodSearchFormEl.addEventListener("submit", function(event) {
    event.preventDefault();

    ingredient = ingredientSearchInput.value.trim();
    diet = dietSelectEl.value;
    time = timeSelectEl.value;

    if (diet === "Choose preferred diet (optional)") {
        diet = undefined;
    }
    if (time === "Choose preferred cook time (optional)") {
        time = undefined;
    }

    ingredientSearchInput.value = "";
    foodModal.classList.add('is-active');
    getFoodRecipe(ingredient, diet, time);
})


clearFavoritesBtn.addEventListener("click", function(event) {
    event.preventDefault();
    localStorage.removeItem("userFoodFavorites");
    savedFood = [];
    showFavorites(savedFood);
})



// Variables for food recipe search API
const foodURL = "https://api.edamam.com/api/recipes/v2?type=public&q=";
const appIDKey = "&app_id=99f65177&app_key=ecb411eb41e5416150875af0c19ffec7";

// Gets data from Edamam API, conditionals to check for which parameters to use in search
function getFoodRecipe(ingredient, diet, time) {
    if (diet && time) {
        fetch(foodURL + ingredient + appIDKey + "&diet=" + diet + "&time=" + time)
            .then(function(response) {
                if (response.ok) {
                    return response.json();
                }
            })
            .then(function(data) {
                if (data.count !== 0) {
                    showRecipes(data.hits);
                } else {
                    throw new Error;
                }
            })
            .catch(function(error) {
                console.log(error);
                invalidIngredient(ingredient);
            })
    } else if (diet && !time) {
        fetch(foodURL + ingredient + appIDKey + "&diet=" + diet)
            .then(function(response) {
                if (response.ok) {
                    return response.json();
                }
            })
            .then(function(data) {
                if (data.count !== 0) {
                    showRecipes(data.hits);
                } else {
                    throw new Error;
                }
            })
            .catch(function(error) {
                console.log(error);
                invalidIngredient(ingredient);
            })
    } else if (!diet && time) {
        fetch(foodURL + ingredient + appIDKey + "&time=" + time)
            .then(function(response) {
                if (response.ok) {
                    return response.json();
                }
            })
            .then(function(data) {
                if (data.count !== 0) {
                    showRecipes(data.hits);
                } else {
                    throw new Error;
                }
            })
            .catch(function(error) {
                console.log(error);
                invalidIngredient(ingredient);
            })
    } else if (!diet && !time) {
        fetch(foodURL + ingredient + appIDKey)
            .then(function(response) {
                if (response.ok) {
                    return response.json();
                }
            })
            .then(function(data) {
                if (data.count !== 0) {
                    showRecipes(data.hits);
                } else {
                    throw new Error;
                }
            })
            .catch(function(error) {
                console.log(error);
                invalidIngredient(ingredient);
            })
    }

}


// Show error message if user searches for invalid ingredient
function invalidIngredient(ingredient) {
    let errorMessageContainer = document.createElement("article");
    errorMessageContainer.setAttribute("class", "card");
    let errorDiv = document.createElement("div");
    errorDiv.setAttribute("class", "card-content");
    let errorMessage = document.createElement("p");
    errorMessage.setAttribute("class", "title is-4 has-text-black");
    errorMessage.textContent = "Sorry, there were no recipes found with that ingredient.";


    modalContentEl.appendChild(errorMessageContainer);
    errorMessageContainer.appendChild(errorDiv);
    errorDiv.appendChild(errorMessage);
}


// Display recipes on cards within modal
function showRecipes(recipes) {

    // Loop through recipes to create an object of necessary info for each recipe
    for (let i = 0; i < recipes.length; i++) {

        let nextRecipe = {
            name: recipes[i].recipe.label,
            image: recipes[i].recipe.image,
            url: recipes[i].recipe.url
        }
        
        // Create elements
        let nextSection = document.createElement("section");

        let nextCard = document.createElement("article");
        nextCard.setAttribute("class", "card m-5 p-5");

        let nextImageDiv = document.createElement("div");
        nextImageDiv.setAttribute("class", "card-image");

        let nextFigure = document.createElement("figure");
        nextFigure.setAttribute("class", "image is-4by3");
        
        let nextImage = document.createElement("img");
        nextImage.setAttribute("src", nextRecipe.image);

        let nextCardContentDiv = document.createElement("div");
        nextCardContentDiv.setAttribute("class", "card-content");

        let nextMediaDiv = document.createElement("div");
        nextMediaDiv.setAttribute("class", "media");

        let nextMediaContent = document.createElement("div");
        nextMediaContent.setAttribute("class", "media-content");

        let nextRecipeName = document.createElement("p");
        nextRecipeName.setAttribute("class", "title is-4 has-text-black");
        nextRecipeName.textContent = nextRecipe.name;

        let nextRecipeURL = document.createElement("p");
        nextRecipeURL.setAttribute("class", "subtitle is-6 has-text-black");

        let nextLink = document.createElement("a");
        nextLink.setAttribute("href", nextRecipe.url);
        nextLink.setAttribute("target", "_blank");
    
        nextLink.textContent = "GO TO FOOD RECIPE";

        let buttonContainer = document.createElement("div");
        buttonContainer.setAttribute("class", "button-container");

        let saveButton = document.createElement("button");
        
        // Style button to show whether a recipe has already been saved
        if (JSON.stringify(savedFood).includes(JSON.stringify(nextRecipe))) {
            saveButton.setAttribute("class", "button is-success");
            saveButton.textContent = "SAVED";
        } else {
            saveButton.setAttribute("class", "button is-info");
            saveButton.textContent = "SAVE ME!";
        }
        let shareButton = document.createElement("button");
        shareButton.setAttribute("class", "button is-primary");
        shareButton.textContent = "SHARE";



        // Append all elements to their parents
        modalContentEl.appendChild(nextSection);
        nextSection.appendChild(nextCard);
        nextCard.appendChild(nextImageDiv);
        nextCard.appendChild(nextCardContentDiv);
        nextImageDiv.appendChild(nextFigure);
        nextFigure.appendChild(nextImage);
        nextCardContentDiv.appendChild(nextMediaDiv);
        nextMediaDiv.appendChild(nextMediaContent);
        nextMediaContent.appendChild(nextRecipeName);
        nextMediaContent.appendChild(nextRecipeURL);
        nextRecipeURL.appendChild(nextLink);
        nextCardContentDiv.appendChild(buttonContainer);
        buttonContainer.appendChild(saveButton);
        buttonContainer.appendChild(shareButton);

        
        saveButton.addEventListener("click", function(event) {
            event.preventDefault();
            if (saveButton.textContent !== "SAVED") {
                savedFood.push(nextRecipe);
                localStorage.setItem("userFoodFavorites", JSON.stringify(savedFood));

                saveButton.setAttribute("class", "button is-success");
                saveButton.textContent = "SAVED";
                showFavorites(savedFood);
            }
        })
        
        shareButton.addEventListener("click", function(event) {
            event.preventDefault();
            if (navigator.share) {
                navigator.share({
                    title: nextRecipe.name,
                    url: nextRecipe.url
                }).then(() => {
                    console.log('Thanks for sharing!');
                }).catch(console.error);
            } else {
                alert('Web Share API is not supported in your browser.');
            }
        });
    }
}


// Display saved recipes from local storage on page load and upon saving a recipe
function showFavorites(savedFood) {

    // Disable the "clear favorites" button if there are no items in the favorites section and enable otherwise
    if (savedFood.length !== 0) {
        clearFavoritesBtn.disabled = false;
    } else {
        clearFavoritesBtn.disabled = true;
    }

    cardsContainer.innerHTML = "";

    for (let i = 0; i < savedFood.length; i++) { 

        let nextRecipe = savedFood[i];

        // Create elements
        let nextCard = document.createElement("article");
        nextCard.setAttribute("class", "card column is-one-quarter m-5 p-5");

        let nextImageDiv = document.createElement("div");
        nextImageDiv.setAttribute("class", "card-image");

        let nextFigure = document.createElement("figure");
        nextFigure.setAttribute("class", "image is-4by3");
        
        let nextImage = document.createElement("img");
        nextImage.setAttribute("src", nextRecipe.image);

        let nextCardContentDiv = document.createElement("div");
        nextCardContentDiv.setAttribute("class", "card-content");

        let nextMediaDiv = document.createElement("div");
        nextMediaDiv.setAttribute("class", "media");

        let nextMediaContent = document.createElement("div");
        nextMediaContent.setAttribute("class", "media-content");

        let nextRecipeName = document.createElement("p");
        nextRecipeName.setAttribute("class", "title is-4 has-text-black");
        nextRecipeName.textContent = nextRecipe.name;

        let nextRecipeURL = document.createElement("p");
        nextRecipeURL.setAttribute("class", "subtitle is-6 has-text-black");
        let nextLink = document.createElement("a");
        nextLink.setAttribute("href", nextRecipe.url);
        nextLink.setAttribute("target", "_blank");
        nextLink.textContent = "GO TO FOOD RECIPE";

        // Append all elements to their parents
        cardsContainer.appendChild(nextCard);
        nextCard.appendChild(nextImageDiv);
        nextCard.appendChild(nextCardContentDiv);
        nextImageDiv.appendChild(nextFigure);
        nextFigure.appendChild(nextImage);
        nextCardContentDiv.appendChild(nextMediaDiv);
        nextMediaDiv.appendChild(nextMediaContent);
        nextMediaContent.appendChild(nextRecipeName);
        nextMediaContent.appendChild(nextRecipeURL);
        nextRecipeURL.appendChild(nextLink);
    }
}

// Run on page load to show favorites from local storage if available
showFavorites(savedFood);