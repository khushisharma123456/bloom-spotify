document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    console.log('DOM Content Loaded');
    
    const elements = {
        professionalsContainer: document.getElementById('professionalsContainer'),
        doctorSearch: document.getElementById('doctorSearch'),
        searchBtn: document.getElementById('searchBtn'),
        filterTags: document.querySelectorAll('.filter-tag'),
        topicItems: document.querySelectorAll('.topics-list li'),
        consultationModal: document.getElementById('consultationModal'),
        modalOverlay: document.getElementById('modalOverlay'),
        closeModalBtn: document.getElementById('closeModal'),
        consultationForm: document.getElementById('consultationForm'),
        confirmationToast: document.getElementById('confirmationToast'),
        appointmentDate: document.getElementById('appointmentDate'),
        doctorName: document.getElementById('doctorName'),
        messageModal: document.getElementById('messageModal'),
        messageModalOverlay: document.getElementById('messageModalOverlay'),
        closeMessageModal: document.getElementById('closeMessageModal'),
        messageForm: document.getElementById('messageForm'),
        messageContainer: document.getElementById('messageContainer'),
        messageText: document.getElementById('messageText'),
        premiumMessage: document.getElementById('premiumMessage')
    };

    console.log('Elements initialized:', elements);    // State management
    const state = {
        professionals: [],
        filters: {
            searchTerm: '',
            category: 'all',
            availability: 'all',
            gender: 'all'
        },
        currentDoctor: null,
        messages: {},
        messageCount: {},
        appointments: [], // Array to store booked appointments
        contactedDoctors: new Set() // Set to store IDs of doctors you've messaged
    };

    // Initialize the application
    function init() {
        console.log('Initializing application');
        setupEventListeners();
        setMinDateForAppointment();
        fetchProfessionals();
        initializeMessages();
        setupMessageEventListeners();
        loadUserData();
        console.log('Application initialized');
    }

    // Set minimum date for appointment (today)
    function setMinDateForAppointment() {
        const today = new Date().toISOString().split('T')[0];
        elements.appointmentDate.min = today;
    }

    // Setup all event listeners
    function setupEventListeners() {
        // Search functionality
        elements.doctorSearch.addEventListener('input', (e) => {
            state.filters.searchTerm = e.target.value.toLowerCase().trim();
            filterProfessionals();
        });

        elements.searchBtn.addEventListener('click', (e) => {
            e.preventDefault();
            filterProfessionals();
        });

        // Filter tags (ensure correct data-filter attributes and active class)
        document.querySelectorAll('.filter-tag').forEach(tag => {
            tag.addEventListener('click', function() {
                document.querySelectorAll('.filter-tag').forEach(t => t.classList.remove('active'));
                this.classList.add('active');
                filterProfessionals();
            });
        });

        // Sidebar topics (categories)
        elements.topicItems.forEach(item => {
            item.addEventListener('click', function() {
                document.querySelectorAll('.topics-list li').forEach(i => i.classList.remove('active'));
                this.classList.add('active');
                filterProfessionals();
            });
        });

        // Modal functionality
        elements.modalOverlay.addEventListener('click', closeModal);
        elements.closeModalBtn.addEventListener('click', closeModal);
        elements.consultationForm.addEventListener('submit', handleFormSubmit);

        // Keyboard events
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && elements.consultationModal.classList.contains('active')) {
                closeModal();
            }
        });
    }

    // Fetch professionals data
    async function fetchProfessionals() {
        try {            const response = await fetch('../templates/data/doctors.json');
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const data = await response.json();
            state.professionals = data.doctors;
            renderProfessionals(state.professionals);
        } catch (error) {
            console.error('Error fetching professionals:', error);
            showError('Failed to load professionals. Please try again later.');
            
            // Fallback to mock data if JSON fetch fails
            console.log('Loading mock data as fallback');
            state.professionals = await mockFetchProfessionals();
            renderProfessionals(state.professionals);
        }
    }

    // Render professionals to the DOM
    function renderProfessionals(professionalsToRender) {
        if (!professionalsToRender || !professionalsToRender.length) {
            showNoResults();
            return;
        }

        // Clear container
        elements.professionalsContainer.innerHTML = '';

        // Create document fragment for better performance
        const fragment = document.createDocumentFragment();

        professionalsToRender.forEach(professional => {
            const professionalCard = createProfessionalCard(professional);
            fragment.appendChild(professionalCard);
        });

        elements.professionalsContainer.appendChild(fragment);
    }

    // Message functions
    function initializeMessages() {
        console.log('Initializing messages');
        // Load messages from localStorage if they exist
        const savedMessages = localStorage.getItem('doctorMessages');
        if (savedMessages) {
            state.messages = JSON.parse(savedMessages);
            console.log('Loaded saved messages:', state.messages);
        }

        const savedMessageCount = localStorage.getItem('messageCount');
        if (savedMessageCount) {
            state.messageCount = JSON.parse(savedMessageCount);
            console.log('Loaded message count:', state.messageCount);
        }
    }

    function openMessageModal(doctorId) {
        console.log('Opening message modal for doctor:', doctorId);
        state.currentDoctor = doctorId;
        elements.messageModal.classList.add('active');
        document.body.style.overflow = 'hidden';
        loadMessages(doctorId);
    }

    function closeMessageModal() {
        elements.messageModal.classList.remove('active');
        document.body.style.overflow = 'auto';
        state.currentDoctor = null;
    }

    function loadMessages(doctorId) {
        console.log('Loading messages for doctor:', doctorId);
        elements.messageContainer.innerHTML = '';
        const messages = state.messages[doctorId] || [];
        
        messages.forEach(message => {
            const messageElement = createMessageElement(message);
            elements.messageContainer.appendChild(messageElement);
        });

        elements.messageContainer.scrollTop = elements.messageContainer.scrollHeight;

        // Check message count and show premium message if needed
        const messageCount = state.messageCount[doctorId] || 0;
        console.log('Message count for doctor:', messageCount);
        
        if (messageCount >= 10) {
            console.log('Showing premium message');
            elements.premiumMessage.style.display = 'flex';
            elements.messageForm.style.display = 'none';
        } else {
            console.log('Showing message form');
            elements.premiumMessage.style.display = 'none';
            elements.messageForm.style.display = 'block';
        }
    }

    function createMessageElement(message) {
        const div = document.createElement('div');
        div.className = `message ${message.sent ? 'sent' : 'received'}`;
        div.textContent = message.text;
        return div;
    }

    function saveMessages() {
        localStorage.setItem('doctorMessages', JSON.stringify(state.messages));
        localStorage.setItem('messageCount', JSON.stringify(state.messageCount));
    }

    function handleMessageSubmit(e) {
        e.preventDefault();
        console.log('Handling message submit');
        
        const doctorId = state.currentDoctor;
        const messageText = elements.messageText.value.trim();
        
        if (!messageText || !doctorId) {
            console.log('Invalid message or doctor ID');
            return;
        }

        console.log('Sending message to doctor:', doctorId);

        // Initialize arrays if they don't exist
        if (!state.messages[doctorId]) {
            state.messages[doctorId] = [];
        }
        if (!state.messageCount[doctorId]) {
            state.messageCount[doctorId] = 0;
        }

        // Check message count
        if (state.messageCount[doctorId] >= 10) {
            console.log('Message limit reached');
            elements.premiumMessage.style.display = 'flex';
            elements.messageForm.style.display = 'none';
            return;
        }

        // Add message
        const message = {
            text: messageText,
            sent: true,
            timestamp: new Date().toISOString()
        };        state.messages[doctorId].push(message);
        state.messageCount[doctorId]++;
        
        // Add doctor to contacted list
        state.contactedDoctors.add(doctorId);

        // Save to localStorage
        saveMessages();
        saveUserData();

        // Clear input and reload messages
        elements.messageText.value = '';
        loadMessages(doctorId);
        console.log('Message sent successfully');

        // Simulate doctor response after 1 second
        setTimeout(() => {
            const response = {
                text: "Thank you for your message. I will get back to you soon.",
                sent: false,
                timestamp: new Date().toISOString()
            };
            state.messages[doctorId].push(response);
            saveMessages();
            loadMessages(doctorId);
            console.log('Doctor response sent');
        }, 1000);
    }

    // Create professional card element
    function createProfessionalCard(professional) {
        const card = document.createElement('div');
        card.className = 'professional-card';
        card.dataset.category = professional.category;
        card.dataset.available = professional.availableToday;
        card.dataset.gender = professional.gender;
        card.dataset.video = professional.videoConsult;

        // Create badges array
        const badges = [];
        if (professional.availableToday) {
            badges.push('<span class="professional-badge">Available Today</span>');
        }
        if (state.appointments.some(apt => apt.doctorId === professional.id)) {
            badges.push('<span class="professional-badge appointment-badge"><i class="fas fa-calendar-check"></i> Upcoming Appointment</span>');
        }
        if (state.contactedDoctors.has(professional.id)) {
            badges.push('<span class="professional-badge contacted-badge"><i class="fas fa-envelope"></i> Contacted</span>');
        }

        // Check if image URL exists, otherwise use default profile emoji
        const imageStyle = professional.image 
            ? `background-image: url('${professional.image}')`
            : `background-color: #f0f0f0; display: flex; align-items: center; justify-content: center; font-size: 48px;`;

        card.innerHTML = `
            <div class="professional-image" style="${imageStyle}">
                ${!professional.image ? '<i class="fas fa-user-circle"></i>' : ''}
                <div class="badge-container">${badges.join('')}</div>
            </div>
            <div class="professional-info">
                <h3 class="professional-name">${professional.name}</h3>
                <span class="professional-specialty">${professional.specialty} • ${professional.location}</span>
                <span class="professional-education">${professional.education}</span>
                <div class="professional-stars">
                    ${renderStars(professional.rating)}
                    <span>(${professional.reviews} reviews)</span>
                </div>                <div class="professional-meta">
                    <span class="professional-price">${professional.price}/consultation</span>
                    <a href="https://www.justdial.com/search?q=${encodeURIComponent(professional.name + ' ' + professional.specialty + ' ' + professional.location)}" target="_blank" class="justdial-link">📞</a>
                </div>
                <div class="professional-description">
                    <p>${professional.description}</p>
                </div>
                <div class="professional-actions">
                    <button class="book-consultation-btn" data-id="${professional.id}">
                        <i class="fas fa-calendar-check"></i> Book Appointment
                    </button>
                    <button class="message-btn" data-id="${professional.id}">
                        <i class="fas fa-envelope"></i> Send Message
                    </button>
                </div>
            </div>
        `;        // Add event listeners to buttons
        card.querySelector('.book-consultation-btn').addEventListener('click', () => {
            openModal(professional);
        });

        card.querySelector('.message-btn').addEventListener('click', () => {
            openMessageModal(professional.id);
        });

        return card;
    }

    // Filter professionals based on current state
    function filterProfessionals() {
        const activeCategoryItem = document.querySelector('.topics-list li.active');
        const activeFilterTag = document.querySelector('.filter-tag.active');
        const searchTerm = elements.doctorSearch.value.toLowerCase().trim();
        const activeCategory = activeCategoryItem ? activeCategoryItem.getAttribute('data-category') : 'all';
        const activeFilter = activeFilterTag ? activeFilterTag.getAttribute('data-filter') : 'all';
        
        let filtered = state.professionals.filter(professional => {
            if (activeFilter === 'appointments') {
                return state.appointments.some(apt => apt.doctorId === professional.id);
            }
            
            if (activeFilter === 'contacted') {
                return state.contactedDoctors.has(professional.id);
            }

            if (activeFilter === 'available') {
                return professional.availableToday;
            }
            
            if (activeFilter === 'female') {
                return professional.gender === 'female';
            }
            
            if (activeCategory !== 'all' && professional.category !== activeCategory) {
                return false;
            }
            
            if (searchTerm) {
                return (professional.name && professional.name.toLowerCase().includes(searchTerm)) ||
                       (professional.specialty && professional.specialty.toLowerCase().includes(searchTerm));
            }
            
            return true;
        });
        
        renderProfessionals(filtered);
    }

    // Helper function to render star ratings
    function renderStars(rating) {
        const fullStars = Math.floor(rating);
        const hasHalfStar = rating % 1 >= 0.5;
        let stars = '';
        
        stars += '<i class="fas fa-star"></i>'.repeat(fullStars);
        stars += hasHalfStar ? '<i class="fas fa-star-half-alt"></i>' : '';
        stars += '<i class="far fa-star"></i>'.repeat(5 - fullStars - (hasHalfStar ? 1 : 0));
        
        return stars;
    }

    // Modal functions
    function openModal(professional) {
        elements.doctorName.value = `${professional.name} - ${professional.specialty}`;
        state.currentDoctor = professional.id; // Store current doctor ID
        elements.consultationModal.classList.add('active');
        document.body.style.overflow = 'hidden';
    }

    function closeModal() {
        elements.consultationModal.classList.remove('active');
        document.body.style.overflow = 'auto';
    }

    // Form handling
    function handleFormSubmit(e) {
        e.preventDefault();
        
        const formData = new FormData(e.target);
        const appointment = {
            doctorId: state.currentDoctor,
            doctorName: elements.doctorName.value,
            date: formData.get('appointmentDate'),
            type: formData.get('consultationType'),
            notes: formData.get('userMessage'),
            timestamp: new Date().toISOString()
        };
        
        // Add to appointments array
        state.appointments.push(appointment);
        
        // Save appointments to localStorage
        saveUserData();
        
        closeModal();
        showConfirmation();
        e.target.reset();
    }

    // UI feedback functions
    function showConfirmation() {
        elements.confirmationToast.classList.add('active');
        setTimeout(() => {
            elements.confirmationToast.classList.remove('active');
        }, 3000);
    }

    function showError(message) {
        elements.professionalsContainer.innerHTML = `
            <div class="error-message">
                <i class="fas fa-exclamation-circle"></i>
                <p>${message}</p>
            </div>
        `;
    }    function showNoResults() {
        // Get active filter
        const activeFilterTag = document.querySelector('.filter-tag.active');
        const activeFilter = activeFilterTag ? activeFilterTag.getAttribute('data-filter') : 'all';
        
        let message = {
            icon: 'fas fa-search',
            title: 'No specialists found',
            description: 'Try adjusting your search or filters'
        };

        // Customize message based on filter
        if (activeFilter === 'appointments') {
            message = {
                icon: 'fas fa-calendar-times',
                title: 'No Appointments Found',
                description: 'You haven\'t booked any appointments yet'
            };
        } else if (activeFilter === 'contacted') {
            message = {
                icon: 'fas fa-envelope',
                title: 'No Contacted Doctors',
                description: 'You haven\'t messaged any doctors yet'
            };
        }

        elements.professionalsContainer.innerHTML = `
            <div class="no-results">
                <i class="${message.icon}"></i>
                <h3>${message.title}</h3>
                <p>${message.description}</p>
            </div>
        `;
    }

    // Mock data fetch (replace with real API call)
    async function mockFetchProfessionals() {
        // Return mock data
        return [
            // Gynecologists
            {
                id: 1,
                name: "Dr. Priya Sharma",
                specialty: "Gynecologist",
                category: "gynecologist",
                image: "Images/doctor1.jpg",
                rating: 4.8,
                reviews: 214,
                price: "₹1200",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "MBBS, MD (Obstetrics & Gynecology) - AIIMS Delhi",
                description: "Senior Consultant at Fortis Hospital, Delhi. Specializes in high-risk pregnancies and minimally invasive surgeries. Over 15 years of experience in women's healthcare.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Fortis-Hospital-Gynecologists"
            },
            {
                id: 2,
                name: "Dr. Meera Bhatia",
                specialty: "Gynecologist",
                category: "gynecologist",
                image: "Images/doctor2.jpg",
                rating: 4.7,
                reviews: 189,
                price: "₹900",
                availableToday: false,
                gender: "female",
                videoConsult: true,
                education: "MBBS, DNB (Obstetrics & Gynecology) - KEM Hospital Mumbai",
                description: "Practicing at Cloud Nine Hospital. Expert in PCOS management and fertility treatments. Known for her patient-centric approach.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Cloud-Nine-Hospital"
            },
            {
                id: 3,
                name: "Dr. Rajesh Kumar",
                specialty: "Gynecologist",
                category: "gynecologist",
                image: "Images/doctor3.jpg",
                rating: 4.9,
                reviews: 276,
                price: "₹1500",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "MBBS, MD, DGO - Manipal Hospital",
                description: "Director of Women's Health at Apollo Hospitals. Pioneering work in laparoscopic surgeries and infertility treatments.",
                location: "Bangalore",
                justdialUrl: "https://www.justdial.com/Bangalore/Apollo-Hospital-Gynecologists"
            },
            {
                id: 4,
                name: "Dr. Amit Tandon",
                specialty: "Gynecologist",
                category: "gynecologist",
                image: "Images/doctor4.jpg",
                rating: 4.6,
                reviews: 167,
                price: "₹1000",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "MBBS, MS (Gynecology) - PGI Chandigarh",
                description: "Senior Consultant at Max Healthcare. Specializes in gynecological oncology and advanced laparoscopic procedures.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Max-Hospital-Gynecologists"
            },
            
            // Ayurvedic Experts
            {
                id: 5,
                name: "Dr. Deepa Krishnan",
                specialty: "Ayurvedic Expert",
                category: "ayurveda",
                image: "Images/doctor5.jpg",
                rating: 4.8,
                reviews: 234,
                price: "₹800",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "BAMS, MD (Ayurveda) - Gujarat Ayurved University",
                description: "Founder of Prakruti Ayurveda Clinic. Expertise in women's health, stress management, and lifestyle disorders.",
                location: "Chennai",
                justdialUrl: "https://www.justdial.com/Chennai/Prakruti-Ayurveda-Clinic"
            },
            {
                id: 6,
                name: "Dr. Smita Naram",
                specialty: "Ayurvedic Expert",
                category: "ayurveda",
                image: "Images/doctor6.jpg",
                rating: 4.9,
                reviews: 312,
                price: "₹1200",
                availableToday: false,
                gender: "female",
                videoConsult: true,
                education: "BAMS, PhD (Ayurveda) - Mumbai University",
                description: "Co-founder of Ayushakti Ayurveda. Pioneer in pulse diagnosis and panchakarma treatments.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Ayushakti-Ayurveda"
            },
            {
                id: 7,
                name: "Dr. Partap Chauhan",
                specialty: "Ayurvedic Expert",
                category: "ayurveda",
                image: "Images/doctor7.jpg",
                rating: 4.7,
                reviews: 289,
                price: "₹900",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "BAMS, MD (Kayachikitsa) - BHU Varanasi",
                description: "Director of Jiva Ayurveda. Known for integrating modern technology with ancient Ayurvedic wisdom.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Jiva-Ayurveda"
            },
            {
                id: 8,
                name: "Dr. Ram Krishna Shastri",
                specialty: "Ayurvedic Expert",
                category: "ayurveda",
                image: "Images/doctor8.jpg",
                rating: 4.6,
                reviews: 178,
                price: "₹700",
                availableToday: true,
                gender: "male",
                videoConsult: false,
                education: "BAMS, MD (Ayurveda) - National Institute of Ayurveda, Jaipur",
                description: "Founder of Ayurvedic Wellness Center. Specializes in natural healing and chronic disease management.",
                location: "Pune",
                justdialUrl: "https://www.justdial.com/Pune/Ayurvedic-Wellness-Center"
            },

            // Fitness Coaches
            {
                id: 9,
                name: "Yasmin Karachiwala",
                specialty: "Fitness Coach",
                category: "fitness",
                image: "Images/coach1.jpg",
                rating: 4.9,
                reviews: 456,
                price: "₹2500",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "ACE Certified, Pilates Instructor - BASI",
                description: "Celebrity fitness trainer. Founder of Body Image. Expert in Pilates and functional training.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Body-Image-Fitness"
            },
            {
                id: 10,
                name: "Sapna Vyas",
                specialty: "Fitness Coach",
                category: "fitness",
                image: "Images/coach2.jpg",
                rating: 4.7,
                reviews: 378,
                price: "₹1800",
                availableToday: false,
                gender: "female",
                videoConsult: true,
                education: "PhD in Health & Fitness, ISSA Certified",
                description: "Transformation specialist and lifestyle coach. Known for sustainable weight loss programs.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Sapna-Vyas-Fitness"
            },
            {
                id: 11,
                name: "Mustafa Ahmed",
                specialty: "Fitness Coach",
                category: "fitness",
                image: "Images/coach3.jpg",
                rating: 4.8,
                reviews: 423,
                price: "₹2000",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "NSCA Certified, Sports Science - Loughborough University",
                description: "Founder of Transformation Zone. Specializes in strength training and athletic performance.",
                location: "Bangalore",
                justdialUrl: "https://www.justdial.com/Bangalore/Transformation-Zone"
            },
            {
                id: 12,
                name: "Ranveer Allahbadia",
                specialty: "Fitness Coach",
                category: "fitness",
                image: "Images/coach4.jpg",
                rating: 4.6,
                reviews: 345,
                price: "₹1500",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "ACE Certified, B.E. in Engineering",
                description: "Founder of BeerBiceps. Holistic approach to fitness combining workout, nutrition, and mindset.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/BeerBiceps-Fitness"
            },

            // Therapists
            {
                id: 13,
                name: "Dr. Rachna Khanna Singh",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist1.jpg",
                rating: 4.9,
                reviews: 289,
                price: "₹2000",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "MD Psychology, The Mind & Wellness Clinic",
                description: "Leading relationship therapist and mental wellness expert. Specializes in anxiety, depression, and couples counseling.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Dr-Rachna-Khanna-Singh"
            },
            {
                id: 14,
                name: "Dr. Shefali Batra",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist2.jpg",
                rating: 4.8,
                reviews: 312,
                price: "₹2500",
                availableToday: false,
                gender: "female",
                videoConsult: true,
                education: "MD Psychiatry, MBBS - Grant Medical College",
                description: "Cognitive behavior therapy expert. Founder of Mindframe. Specializes in women's mental health.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Dr-Shefali-Batra"
            },
            {
                id: 15,
                name: "Dr. Sayeli Jaiswal",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist3.jpg",
                rating: 4.7,
                reviews: 267,
                price: "₹1800",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "PhD Clinical Psychology - Christ University",
                description: "Expert in trauma therapy and EMDR. Specializes in anxiety disorders and PTSD treatment.",
                location: "Bangalore",
                justdialUrl: "https://www.justdial.com/Bangalore/Dr-Sayeli-Jaiswal"
            },
            {
                id: 16,
                name: "Dr. Kamna Chhibber",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist4.jpg",
                rating: 4.8,
                reviews: 345,
                price: "₹2200",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "M.Phil Clinical Psychology - IHBAS",
                description: "Head of Mental Health at Fortis Healthcare. Expert in cognitive behavioral therapy and mindfulness.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Dr-Kamna-Chhibber"
            },
            {
                id: 17,
                name: "Dr. Kersi Chavda",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist5.jpg",
                rating: 4.9,
                reviews: 378,
                price: "₹2500",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "MD Psychiatry - Hinduja Hospital",
                description: "Consultant psychiatrist at Hinduja Hospital. Expert in mood disorders and addiction treatment.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Dr-Kersi-Chavda"
            },
            {
                id: 18,
                name: "Dr. Achal Bhagat",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist6.jpg",
                rating: 4.7,
                reviews: 289,
                price: "₹2300",
                availableToday: false,
                gender: "male",
                videoConsult: true,
                education: "MD Psychiatry - AIIMS Delhi",
                description: "Senior consultant psychiatrist at Apollo Hospital. Specializes in stress management and depression.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Dr-Achal-Bhagat"
            },
            {
                id: 19,
                name: "Dr. Harish Shetty",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist7.jpg",
                rating: 4.8,
                reviews: 334,
                price: "₹2000",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "MD Psychiatry - Dr LH Hiranandani Hospital",
                description: "Social psychiatrist specializing in community mental health and family therapy.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Dr-Harish-Shetty"
            },
            {
                id: 20,
                name: "Dr. Samir Parikh",
                specialty: "Therapist",
                category: "support",
                image: "Images/therapist8.jpg",
                rating: 4.9,
                reviews: 412,
                price: "₹2400",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "MD Psychiatry - Fortis Healthcare",
                description: "Director of Mental Health and Behavioral Sciences at Fortis Healthcare. Expert in youth mental health.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Dr-Samir-Parikh"
            },

            // Nutritionists
            {
                id: 17,
                name: "Dr. Rujuta Diwekar",
                specialty: "Nutritionist",
                category: "nutritionist",
                image: "Images/nutritionist1.jpg",
                rating: 4.9,
                reviews: 567,
                price: "₹3000",
                availableToday: true,
                gender: "female",
                videoConsult: true,
                education: "MSc Sports Science - Mumbai University",
                description: "Celebrity nutritionist. Advocates traditional Indian eating habits with modern nutritional science.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Rujuta-Diwekar-Nutrition"
            },
            {
                id: 18,
                name: "Dr. Ishi Khosla",
                specialty: "Nutritionist",
                category: "nutritionist",
                image: "Images/nutritionist2.jpg",
                rating: 4.8,
                reviews: 423,
                price: "₹2500",
                availableToday: false,
                gender: "female",
                videoConsult: true,
                education: "MSc Food & Nutrition - Delhi University",
                description: "Founder of Whole Foods India. Expert in celiac disease and therapeutic nutrition.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Whole-Foods-India"
            },
            {
                id: 19,
                name: "Dr. Nikhil Dhurandhar",
                specialty: "Nutritionist",
                category: "nutritionist",
                image: "Images/nutritionist3.jpg",
                rating: 4.7,
                reviews: 389,
                price: "₹2000",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "PhD Nutrition - Bombay University",
                description: "Obesity researcher and clinical nutritionist. Known for evidence-based approach to weight management.",
                location: "Mumbai",
                justdialUrl: "https://www.justdial.com/Mumbai/Dr-Nikhil-Dhurandhar"
            },
            {
                id: 20,
                name: "Dr. Manjari Chandra",
                specialty: "Nutritionist",
                category: "nutritionist",
                image: "Images/nutritionist4.jpg",
                rating: 4.6,
                reviews: 312,
                price: "₹1800",
                availableToday: true,
                gender: "male",
                videoConsult: true,
                education: "PhD Clinical Nutrition - Max Healthcare",
                description: "Functional nutrition expert. Specializes in gut health and autoimmune conditions.",
                location: "Delhi",
                justdialUrl: "https://www.justdial.com/Delhi/Dr-Manjari-Chandra"
            }
        ];
    }

    // Additional event listeners for messaging
    function setupMessageEventListeners() {
        console.log('Setting up message event listeners');
        
        // Close message modal
        elements.messageModalOverlay.addEventListener('click', () => {
            console.log('Message modal overlay clicked');
            closeMessageModal();
        });
        
        elements.closeMessageModal.addEventListener('click', () => {
            console.log('Close message modal button clicked');
            closeMessageModal();
        });
        
        // Handle message form submission
        elements.messageForm.addEventListener('submit', (e) => {
            console.log('Message form submitted');
            handleMessageSubmit(e);
        });

        // Add click handlers to all message buttons
        document.querySelectorAll('.message-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const doctorId = btn.getAttribute('data-id');
                console.log('Message button clicked for doctor:', doctorId);
                openMessageModal(doctorId);
            });
        });
    }

    function loadUserData() {
        // Load appointments
        const savedAppointments = localStorage.getItem('userAppointments');
        if (savedAppointments) {
            state.appointments = JSON.parse(savedAppointments);
        }

        // Load contacted doctors
        const savedContacts = localStorage.getItem('contactedDoctors');
        if (savedContacts) {
            state.contactedDoctors = new Set(JSON.parse(savedContacts));
        }
    }

    function saveUserData() {
        localStorage.setItem('userAppointments', JSON.stringify(state.appointments));
        localStorage.setItem('contactedDoctors', JSON.stringify([...state.contactedDoctors]));
    }

    // Call init() to start the application
    init();
});