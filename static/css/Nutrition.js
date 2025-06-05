// Nutrition.js

document.addEventListener('DOMContentLoaded', function() {
    // Navigation functionality
    const navItems = document.querySelectorAll('.nav-item');
    const contentSections = document.querySelectorAll('.content-section');
    
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from all nav items and sections
            navItems.forEach(navItem => navItem.classList.remove('active'));
            contentSections.forEach(section => section.classList.remove('active'));
            
            // Add active class to clicked nav item
            this.classList.add('active');
            
            // Show corresponding section
            const sectionId = this.getAttribute('data-section');
            document.getElementById(sectionId).classList.add('active');
        });
    });

    // Water Tracker Functionality
    const waterButtons = document.querySelectorAll('.water-btn');
    const waterFill = document.querySelector('.water-fill');
    const waterAmount = document.querySelector('.water-amount');
    const progressFill = document.querySelector('.progress-fill');
    const progressText = document.querySelector('.water-progress span');
    const dailyGoal = 2000; // 2L in ml

    // Load from localStorage or start at 0
    let currentWater = parseInt(localStorage.getItem('currentWaterIntake')) || 0;

    function updateWaterDisplay() {
        const percentage = (currentWater / dailyGoal) * 100;
        const liters = (currentWater / 1000).toFixed(1);
        if (waterFill) waterFill.style.height = `${percentage}%`;
        if (waterAmount) waterAmount.textContent = `${liters}L`;
        if (progressFill) progressFill.style.width = `${percentage}%`;
        if (progressText) progressText.textContent = `${Math.round(percentage)}% of daily goal`;
    }

    waterButtons.forEach(button => {
        button.addEventListener('click', function() {
            let amount = 0;
            if (this.textContent.includes('250')) amount = 250;
            if (this.textContent.includes('500')) amount = 500;
            currentWater += amount;
            if (currentWater > dailyGoal) currentWater = dailyGoal;
            localStorage.setItem('currentWaterIntake', currentWater); // Save to localStorage
            updateWaterDisplay();
        });
    });

    updateWaterDisplay(); // Initialize UI with saved or 0 value

    // Ayurveda Section - Category Filter
    const categoryButtons = document.querySelectorAll('.category-btn');
    
    categoryButtons.forEach(button => {
        button.addEventListener('click', function() {
            categoryButtons.forEach(btn => btn.classList.remove('active'));
            this.classList.add('active');
            
            const category = this.textContent;
            filterRemedies(category);
        });
    });
    
    function filterRemedies(category) {
        if (category === 'All') {
            remedyCards.forEach(card => card.style.display = 'block');
            return;
        }
        
        remedyCards.forEach(card => {
            const badgeElem = card.querySelector('.recipe-badge');
            const badge = badgeElem ? badgeElem.textContent : '';
            const display = badge.includes(category) ? 'block' : 'none';
            card.style.display = display;
        });
    }

    // Recipe Section - Filter Functionality
    const phaseFilter = document.querySelector('.recipe-filters select:first-child');
    const mealFilter = document.querySelector('.recipe-filters select:last-child');
    const recipeCards = document.querySelectorAll('.recipe-card');

    function filterRecipes() {
        const selectedPhase = phaseFilter.value;
        const selectedMeal = mealFilter.value;
        recipeCards.forEach(card => {
            const phase = card.getAttribute('data-phase') || 'All';
            const meal = card.getAttribute('data-meal') || 'All';
            // Show all if both filters are 'All'
            const show = (selectedPhase === 'All' && selectedMeal === 'All') ||
                         (selectedPhase === 'All' && meal.includes(selectedMeal)) ||
                         (selectedMeal === 'All' && phase.includes(selectedPhase)) ||
                         (phase.includes(selectedPhase) && meal.includes(selectedMeal));
            card.style.display = show ? 'block' : 'none';
        });
    }

    phaseFilter.addEventListener('change', filterRecipes);
    mealFilter.addEventListener('change', filterRecipes);

    // Initial filter
    filterRecipes();

    // View Recipe Buttons
    document.querySelectorAll('.view-recipe').forEach(button => {
        button.addEventListener('click', function() {
            const recipeName = this.closest('.recipe-info').querySelector('h3').textContent;
            window.location.href = `/remedy/${encodeURIComponent(recipeName)}`;
        });
    });

    // Home Button
    const homeButton = document.querySelector('.home');
    homeButton.addEventListener('click', function() {
        alert('Navigating to Home Screen');
        // In a real app, this would navigate to the home page
    });

    // Profile Button
    const profileButton = document.querySelector('.profile');
    profileButton.addEventListener('click', function() {
        alert('Opening Profile Settings');
        // In a real app, this would open the user profile
    });

    // Search Functionality
    const searchBox = document.querySelector('.search-box input');
    const searchButton = document.querySelector('.search-box button');
    // Declare remedyCards ONCE here
    const remedyCards = document.querySelectorAll('.remedy-grid .recipe-card');

    function performSearch() {
        const searchTerm = searchBox.value.trim().toLowerCase();
        remedyCards.forEach(card => {
            const text = card.textContent.toLowerCase();
            card.style.display = searchTerm === '' || text.includes(searchTerm) ? 'block' : 'none';
        });
    }

    if (searchButton && searchBox) {
        searchButton.addEventListener('click', performSearch);
        searchBox.addEventListener('input', performSearch); // Filter as you type
        searchBox.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') performSearch();
        });
    }
});