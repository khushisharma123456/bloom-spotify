// chatbot.js
document.addEventListener('DOMContentLoaded', async function() {
    try {
        // Load API key first
        await loadApiKey();
        
        // Then load prompt template
        const template = await loadPromptTemplate();
        if (!template) {
            console.error('Failed to load prompt template');
        }
    } catch (error) {
        console.error('Initialization error:', error);
    }

    // DOM Elements
    const chatContainer = document.getElementById('chatContainer');
    const userInput = document.getElementById('userInput');
    const sendButton = document.getElementById('sendBtn');
    const chatHistoryList = document.getElementById('chatHistoryList');
    const newChatBtn = document.getElementById('newChatBtn');
    const clearHistoryBtn = document.querySelector('.clear-history');
    const welcomeScreen = document.getElementById('welcomeScreen');
    const chatMessages = document.getElementById('chatMessages');

    // State variables
    let currentChatId = null;
    let chats = JSON.parse(localStorage.getItem('chats')) || {};
    let isTyping = false;

    // Speech Recognition Setup
    const micBtn = document.getElementById('micBtn');
    let recognition = null;
    let isRecording = false;

    // File handling setup
    const fileInput = document.getElementById('fileInput');
    const attachmentDropdown = document.getElementById('attachmentDropdown');
    const attachmentBtn = document.getElementById('attachmentBtn');

    // Add these variables at the top of the file
    let GEMINI_API_KEY = '';
    const PROMPT_TEMPLATE_PATH = 'templates/prompt_template.txt';

    // Initialize the chat
    initChat();

    // Event Listeners
    if (sendButton) {
        sendButton.addEventListener('click', sendMessage);
    }
    if (userInput) {
        userInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter' && !isTyping) {
                sendMessage();
            }
        });
    }
    if (newChatBtn) {
        newChatBtn.addEventListener('click', createNewChat);
    }
    if (clearHistoryBtn) {
        clearHistoryBtn.addEventListener('click', clearChatHistory);
    }

    // Handle attachment dropdown items
    document.querySelectorAll('.dropdown-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.preventDefault();
            const type = this.getAttribute('data-type');
            handleAttachment(type);
        });
    });

    // Initialize speech recognition
    function initSpeechRecognition() {
        if ('webkitSpeechRecognition' in window) {
            recognition = new webkitSpeechRecognition();
            recognition.continuous = false;
            recognition.interimResults = true;
            recognition.lang = 'en-US';

            recognition.onstart = function() {
                isRecording = true;
                micBtn.classList.add('recording');
                showToast('Listening...');
            };

            recognition.onresult = function(event) {
                const transcript = Array.from(event.results)
                    .map(result => result[0].transcript)
                    .join('');
                
                userInput.value = transcript;
            };

            recognition.onerror = function(event) {
                console.error('Speech recognition error:', event.error);
                showToast('Error: ' + event.error);
                stopRecording();
            };

            recognition.onend = function() {
                stopRecording();
            };
        } else {
            micBtn.style.display = 'none';
            console.error('Speech recognition not supported');
        }
    }

    // Start recording
    function startRecording() {
        if (recognition && !isRecording) {
            recognition.start();
        }
    }

    // Stop recording
    function stopRecording() {
        if (recognition && isRecording) {
            recognition.stop();
            isRecording = false;
            micBtn.classList.remove('recording');
        }
    }

    // Toggle recording
    function toggleRecording() {
        if (isRecording) {
            stopRecording();
        } else {
            startRecording();
        }
    }

    // Initialize speech recognition
    initSpeechRecognition();

    // Add click event listener to microphone button
    if (micBtn) {
        micBtn.addEventListener('click', toggleRecording);
    }

    // Modify sendMessage to handle speech input
    const originalSendMessage = sendMessage;
    sendMessage = function() {
        if (isRecording) {
            stopRecording();
        }
        originalSendMessage();
    };

    // Initialize chat
    function initChat() {
        renderChatHistory();
        showWelcomeScreen();
    }

    // Show welcome screen
    function showWelcomeScreen() {
        welcomeScreen.style.display = 'flex';
        chatMessages.style.display = 'none';
        currentChatId = null;
    }

    // Create new chat
    function createNewChat() {
        currentChatId = generateChatId();
        chats[currentChatId] = {
            id: currentChatId,
            title: 'New Chat',
            messages: [],
            timestamp: new Date().toISOString()
        };
        saveChats();
        welcomeScreen.style.display = 'none';
        chatMessages.style.display = 'block';
        renderMessages();
        renderChatHistory();
    }

    // Modify sendMessage to handle file uploads
    sendMessage = async function() {
        if (isRecording) {
            stopRecording();
        }

        const message = userInput.value.trim();
        const filePreviews = document.querySelectorAll('.file-preview');
        
        if ((message === '' && filePreviews.length === 0) || isTyping) return;

        // If no current chat exists, create one
        if (!currentChatId) {
            createNewChat();
        }

        // Add user message to chat
        addMessageToChat('user', message);
        userInput.value = '';
        
        // Process attachments if any
        if (filePreviews.length > 0) {
            const attachments = Array.from(filePreviews).map(preview => {
                const fileData = preview.querySelector('img, video, .preview-file');
                return {
                    type: fileData.tagName.toLowerCase(),
                    data: fileData.tagName === 'IMG' ? fileData.src :
                          fileData.tagName === 'VIDEO' ? fileData.querySelector('source').src :
                          fileData.querySelector('.file-size').textContent,
                    fileName: preview.querySelector('.preview-title').textContent
                };
            });
            
            // Add attachments to the message
            chats[currentChatId].messages[chats[currentChatId].messages.length - 1].attachments = attachments;
            saveChats();
            
            // Clear previews
            filePreviews.forEach(preview => preview.remove());
        }
        
        // Show typing indicator
        showTypingIndicator();
        
        // Generate AI response after a delay
        setTimeout(() => {
            hideTypingIndicator();
            generateAIResponse(message);
        }, 1500);
    };

    // Add message to chat
    function addMessageToChat(sender, text) {
        const message = {
            sender,
            text,
            timestamp: new Date().toISOString()
        };
        
        chats[currentChatId].messages.push(message);
        saveChats();
        renderMessages();
        
        // Update chat title if it's the first user message
        if (sender === 'user' && chats[currentChatId].messages.length === 1) {
            updateChatTitle(text);
        }
    }

    // Render all messages in current chat
    function renderMessages() {
        if (!chatMessages) return;
        
        chatMessages.innerHTML = '';
        
        chats[currentChatId]?.messages?.forEach((msg, index) => {
            if (msg.sender === 'user') {
                chatMessages.appendChild(createUserMessageElement(msg.text, msg.timestamp, index));
            } else {
                chatMessages.appendChild(createAIMessageElement(msg.text, msg.timestamp, index));
            }
        });
        
        scrollToBottom();
    }

    // Create user message element with all functionality
    function createUserMessageElement(text, timestamp, messageIndex) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'user-prompt';
        messageDiv.dataset.messageIndex = messageIndex;
        
        const message = chats[currentChatId].messages[messageIndex];
        let attachmentsHtml = '';
        
        if (message.attachments && message.attachments.length > 0) {
            attachmentsHtml = message.attachments.map(attachment => {
                if (attachment.type === 'img') {
                    return `<div class="message-attachment"><img src="${attachment.data}" alt="Attached image"></div>`;
                } else if (attachment.type === 'video') {
                    return `<div class="message-attachment"><video controls><source src="${attachment.data}" type="video/mp4"></video></div>`;
                } else {
                    return `<div class="message-attachment"><i class="fas fa-file"></i> ${attachment.data}</div>`;
                }
            }).join('');
        }
        
        messageDiv.innerHTML = `
            <div class="up">
                <i class="fas fa-user-circle" style="font-size: 24px; color: white;"></i>
                <div class="message-content">
                    <p class="message-text">${text}</p>
                    ${attachmentsHtml}
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="far fa-copy"></i>
                        </button>
                        <button class="action-btn edit-btn" title="Edit">
                            <i class="far fa-edit"></i>
                        </button>
                        <button class="action-btn delete-btn" title="Delete">
                            <i class="far fa-trash-alt"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Add functionality to buttons
        addMessageFunctionality(messageDiv, text, messageIndex);
        
        return messageDiv;
    }

    // Create AI message element with all functionality
    function createAIMessageElement(text, timestamp, messageIndex) {
        const messageDiv = document.createElement('div');
        messageDiv.className = 'ai-prompt';
        messageDiv.dataset.messageIndex = messageIndex;
        
        messageDiv.innerHTML = `
            <div class="up">
                <img src="static/Images/logo1.png" alt="Bloom AI" class="ai-logo">
                <div class="message-content">
                    <p class="message-text">${text}</p>
                    <div class="message-actions">
                        <button class="action-btn copy-btn" title="Copy">
                            <i class="far fa-copy"></i>
                        </button>
                        <button class="action-btn thumbs-up" title="Helpful">
                            <i class="far fa-thumbs-up"></i>
                        </button>
                        <button class="action-btn thumbs-down" title="Not helpful">
                            <i class="far fa-thumbs-down"></i>
                        </button>
                        <button class="action-btn delete-btn" title="Delete">
                            <i class="far fa-trash-alt"></i>
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        // Add functionality to buttons
        addMessageFunctionality(messageDiv, text, messageIndex);
        
        return messageDiv;
    }

    // Add functionality to message buttons
    function addMessageFunctionality(messageDiv, text, messageIndex) {
        // Copy button
        const copyBtn = messageDiv.querySelector('.copy-btn');
        if (copyBtn) {
            copyBtn.addEventListener('click', () => {
                navigator.clipboard.writeText(text)
                    .then(() => showToast('Message copied to clipboard!'))
                    .catch(err => console.error('Failed to copy:', err));
            });
        }
        
        // Edit button (only for user messages)
        const editBtn = messageDiv.querySelector('.edit-btn');
        if (editBtn) {
            editBtn.addEventListener('click', () => editMessage(messageDiv, text, messageIndex));
        }
        
        // Delete button
        const deleteBtn = messageDiv.querySelector('.delete-btn');
        if (deleteBtn) {
            deleteBtn.addEventListener('click', () => deleteMessage(messageIndex));
        }
        
        // Feedback buttons (only for AI messages)
        const thumbsUp = messageDiv.querySelector('.thumbs-up');
        if (thumbsUp) {
            thumbsUp.addEventListener('click', () => rateMessage(messageIndex, 'positive'));
        }
        
        const thumbsDown = messageDiv.querySelector('.thumbs-down');
        if (thumbsDown) {
            thumbsDown.addEventListener('click', () => rateMessage(messageIndex, 'negative'));
        }
    }

    // Edit message functionality
    function editMessage(messageDiv, originalText, messageIndex) {
        const messageContent = messageDiv.querySelector('.message-content');
        if (!messageContent) return;
        
        messageContent.innerHTML = `
            <textarea class="edit-textarea">${originalText}</textarea>
            <div class="edit-actions">
                <button class="action-btn save-edit">Save</button>
                <button class="action-btn cancel-edit">Cancel</button>
            </div>
        `;
        
        const textarea = messageContent.querySelector('.edit-textarea');
        textarea.focus();
        textarea.setSelectionRange(textarea.value.length, textarea.value.length);
        
        const saveBtn = messageContent.querySelector('.save-edit');
        const cancelBtn = messageContent.querySelector('.cancel-edit');
        
        saveBtn.addEventListener('click', () => {
            const newText = textarea.value.trim();
            if (newText && newText !== originalText) {
                updateMessageText(messageIndex, newText);
            }
            renderMessages();
        });
        
        cancelBtn.addEventListener('click', renderMessages);
    }

    // Delete message functionality
    function deleteMessage(messageIndex) {
        if (confirm('Are you sure you want to delete this message?')) {
            chats[currentChatId].messages.splice(messageIndex, 1);
            saveChats();
            renderMessages();
            
            // Update chat title if we deleted the first message
            if (chats[currentChatId].messages.length === 0) {
                updateChatTitle('New Chat');
            }
        }
    }

    // Rate message functionality
    function rateMessage(messageIndex, rating) {
        if (chats[currentChatId] && chats[currentChatId].messages[messageIndex]) {
            chats[currentChatId].messages[messageIndex].rating = rating;
            saveChats();
            showToast(`Thank you for your feedback!`);
        }
    }

    // Update message text in chat history
    function updateMessageText(messageIndex, newText) {
        if (chats[currentChatId] && chats[currentChatId].messages[messageIndex]) {
            chats[currentChatId].messages[messageIndex].text = newText;
            saveChats();
            
            // Update chat title if this was the first message
            if (messageIndex === 0) {
                updateChatTitle(newText);
            }
        }
    }

    // Render chat history list
    function renderChatHistory() {
        if (!chatHistoryList) return;
        
        chatHistoryList.innerHTML = '';
        
        if (Object.keys(chats).length === 0) {
            chatHistoryList.innerHTML = '<p class="no-history-message">No previous chats</p>';
            return;
        }
        
        // Sort chats by timestamp (newest first)
        const sortedChats = Object.values(chats).sort((a, b) => 
            new Date(b.timestamp) - new Date(a.timestamp)
        );
        
        sortedChats.forEach(chat => {
            const chatItem = document.createElement('div');
            chatItem.className = `chat-history-item ${chat.id === currentChatId ? 'active' : ''}`;
            
            const date = new Date(chat.timestamp);
            const dateStr = date.toLocaleDateString('en-US', { 
                month: 'short', 
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit'
            });
            
            // Get the first user message as preview if available
            const firstUserMessage = chat.messages.find(msg => msg.sender === 'user');
            const previewText = firstUserMessage ? 
                firstUserMessage.text.substring(0, 30) + (firstUserMessage.text.length > 30 ? '...' : '') : 
                'New Chat';
            
            chatItem.innerHTML = `
                <div class="chat-info">
                    <div class="chat-date">${dateStr}</div>
                    <div class="chat-preview">${previewText}</div>
                </div>
                <button class="delete-chat-btn" title="Delete chat">
                    <i class="far fa-trash-alt"></i>
                </button>
            `;
            
            // Load chat when clicked
            chatItem.addEventListener('click', () => loadChat(chat.id));
            
            // Delete chat button
            const deleteBtn = chatItem.querySelector('.delete-chat-btn');
            if (deleteBtn) {
                deleteBtn.addEventListener('click', (e) => {
                    e.stopPropagation();
                    deleteChatFromHistory(chat.id);
                });
            }
            
            chatHistoryList.appendChild(chatItem);
        });
    }

    // Delete chat from history
    function deleteChatFromHistory(chatId) {
        if (confirm('Are you sure you want to delete this chat?')) {
            delete chats[chatId];
            saveChats();
            
            // If we deleted the current chat, create a new one
            if (chatId === currentChatId) {
                createNewChat();
            } else {
                renderChatHistory();
            }
        }
    }

    // Load specific chat
    function loadChat(chatId) {
        currentChatId = chatId;
        welcomeScreen.style.display = 'none';
        chatMessages.style.display = 'block';
        renderMessages();
        renderChatHistory();
    }

    // Update chat title
    function updateChatTitle(firstMessage) {
        const title = firstMessage.substring(0, 30) + (firstMessage.length > 30 ? '...' : '');
        chats[currentChatId].title = title;
        saveChats();
        renderChatHistory();
    }

    // Clear all chat history
    function clearChatHistory() {
        if (confirm('Are you sure you want to clear all chat history?')) {
            chats = {};
            saveChats();
            showWelcomeScreen();
            renderChatHistory();
        }
    }

    // Save chats to localStorage
    function saveChats() {
        localStorage.setItem('chats', JSON.stringify(chats));
    }

    // Show typing indicator
    function showTypingIndicator() {
        isTyping = true;
        const typingDiv = document.createElement('div');
        typingDiv.className = 'ai-prompt typing-indicator';
        typingDiv.innerHTML = `
            <div class="up">
                <img src="static/Images/logo1.png" alt="Bloom AI" class="ai-logo">
                <div class="message-content">
                    <div class="typing-dots">
                        <div class="dot"></div>
                        <div class="dot"></div>
                        <div class="dot"></div>
                    </div>
                </div>
            </div>
        `;
        chatContainer.appendChild(typingDiv);
        scrollToBottom();
    }

    // Hide typing indicator
    function hideTypingIndicator() {
        isTyping = false;
        const typingIndicator = document.querySelector('.typing-indicator');
        if (typingIndicator) {
            typingIndicator.remove();
        }
    }

    // Show toast notification
    function showToast(message) {
        const toast = document.createElement('div');
        toast.className = 'toast-notification';
        toast.textContent = message;
        document.body.appendChild(toast);
        
        setTimeout(() => {
            toast.classList.add('show');
        }, 10);
        
        setTimeout(() => {
            toast.classList.remove('show');
            setTimeout(() => {
                toast.remove();
            }, 300);
        }, 3000);
    }

    // Scroll chat to bottom
    function scrollToBottom() {
        if (chatContainer) {
            chatContainer.scrollTop = chatContainer.scrollHeight;
        }
    }

    // Generate chat ID
    function generateChatId() {
        return 'chat-' + Math.random().toString(36).substr(2, 9);
    }

    // Function to load API key from .env file
    async function loadApiKey() {
        try {
            const response = await fetch('../../../.env');
            if (!response.ok) {
                throw new Error(`Failed to load .env file: ${response.status}`);
            }
            const text = await response.text();
            const match = text.match(/GEMINI_API_KEY=(.+)/);
            if (match && match[1]) {
                GEMINI_API_KEY = match[1].trim();
                console.log('API key loaded successfully');
            } else {
                throw new Error('API key not found in .env file');
            }
        } catch (error) {
            console.error('Error loading API key:', error);
            throw new Error('Failed to load API key: ' + error.message);
        }
    }

    // Function to load prompt template
    async function loadPromptTemplate() {
        try {
            const response = await fetch(PROMPT_TEMPLATE_PATH);
            return await response.text();
        } catch (error) {
            console.error('Error loading prompt template:', error);
            return null;
        }
    }

    // Function to format prompt with user query
    function formatPrompt(template, userQuery) {
        return template.replace('{USER_QUERY}', userQuery);
    }

    // Function to call Gemini API
    async function callGeminiAPI(prompt) {
        try {
            if (!GEMINI_API_KEY) {
                throw new Error('API key not loaded');
            }

            console.log('Calling Gemini API...');
            const response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'x-goog-api-key': GEMINI_API_KEY
                },
                body: JSON.stringify({
                    contents: [{
                        parts: [{
                            text: prompt
                        }]
                    }]
                })
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(`API request failed: ${response.status} - ${JSON.stringify(errorData)}`);
            }

            const data = await response.json();
            console.log('API Response:', data);
            
            if (!data.candidates || !data.candidates[0] || !data.candidates[0].content) {
                throw new Error('Invalid API response format');
            }

            return data.candidates[0].content.parts[0].text;
        } catch (error) {
            console.error('Error calling Gemini API:', error);
            throw new Error('Failed to get response from AI: ' + error.message);
        }
    }

    // Modify the existing generateAIResponse function
    async function generateAIResponse(userMessage) {
        try {
            // Load prompt template
            const template = await loadPromptTemplate();
            if (!template) {
                throw new Error('Failed to load prompt template');
            }

            // Format prompt with user message
            const formattedPrompt = formatPrompt(template, userMessage);
            console.log('Formatted prompt:', formattedPrompt);

            // Call Gemini API
            const aiResponse = await callGeminiAPI(formattedPrompt);

            // Add AI response to chat
            addMessageToChat('assistant', aiResponse);
            
            // Save chat
            saveChats();
        } catch (error) {
            console.error('Error generating AI response:', error);
            addMessageToChat('assistant', `I apologize, but I encountered an error: ${error.message}. Please try again.`);
        }
    }

    // Handle attachment selection
    function handleAttachment(type) {
        // Set accept attribute based on type
        switch(type) {
            case 'photo':
                fileInput.accept = 'image/*';
                break;
            case 'video':
                fileInput.accept = 'video/*';
                break;
            case 'file':
                fileInput.accept = '*/*';
                break;
        }

        // Trigger file input click
        fileInput.click();
    }

    // Handle file selection
    fileInput.addEventListener('change', async function(e) {
        const file = e.target.files[0];
        if (file) {
            try {
                // Show loading state
                showToast('Processing file...');
                
                // Check file size (limit to 10MB)
                const maxSize = 10 * 1024 * 1024; // 10MB in bytes
                if (file.size > maxSize) {
                    showToast('File size too large. Please upload a file less than 10MB');
                    // Add a message to the chat about the file size limit
                    addMessageToChat('assistant', 'I notice you tried to upload a file. Please make sure your file is less than 10MB in size. You can try compressing the file or choosing a smaller one.');
                    return;
                }

                // Validate file type before processing
                const fileType = fileInput.accept;
                if (fileType.includes('image') && !file.type.startsWith('image/')) {
                    showToast('Please select a valid image file (JPG, PNG, GIF)');
                    addMessageToChat('assistant', 'I can only process image files in JPG, PNG, or GIF format. Please try again with a supported image file.');
                    return;
                }
                if (fileType.includes('video') && !file.type.startsWith('video/')) {
                    showToast('Please select a valid video file (MP4, WebM)');
                    addMessageToChat('assistant', 'I can only process video files in MP4 or WebM format. Please try again with a supported video file.');
                    return;
                }

                // Read file as base64 with timeout
                const base64File = await Promise.race([
                    readFileAsBase64(file),
                    new Promise((_, reject) => 
                        setTimeout(() => reject(new Error('File processing timeout')), 30000)
                    )
                ]);
                
                // Create a preview message
                const previewMessage = {
                    type: fileInput.accept.includes('image') ? 'photo' : 
                          fileInput.accept.includes('video') ? 'video' : 'file',
                    fileName: file.name,
                    fileSize: formatFileSize(file.size),
                    fileData: base64File,
                    timestamp: new Date().toISOString(),
                    mimeType: file.type
                };
                
                // Add preview to chat
                addFilePreviewToChat(previewMessage);
                
                // Store file data in current chat
                if (!chats[currentChatId].attachments) {
                    chats[currentChatId].attachments = [];
                }
                chats[currentChatId].attachments.push(previewMessage);
                saveChats();
                
                showToast('File ready to send');
            } catch (error) {
                console.error('Error processing file:', error);
                let errorMessage = 'Error processing file';
                
                if (error.message === 'File processing timeout') {
                    errorMessage = 'File processing took too long. Please try a smaller file.';
                } else if (error.message.includes('Failed to read file')) {
                    errorMessage = 'Unable to read the file. Please make sure it\'s not corrupted.';
                }
                
                showToast(errorMessage);
                addMessageToChat('assistant', `I encountered an issue while processing your file: ${errorMessage}. Please try again with a different file.`);
            } finally {
                // Reset file input
                fileInput.value = '';
            }
        }
    });

    // Read file as base64 with error handling
    function readFileAsBase64(file) {
        return new Promise((resolve, reject) => {
            const reader = new FileReader();
            
            reader.onload = () => {
                try {
                    // Validate the base64 data
                    const base64Data = reader.result;
                    if (!base64Data.startsWith('data:')) {
                        throw new Error('Invalid file data');
                    }
                    resolve(base64Data);
                } catch (error) {
                    reject(new Error('Failed to process file data'));
                }
            };
            
            reader.onerror = (error) => {
                console.error('Error reading file:', error);
                reject(new Error('Failed to read file'));
            };
            
            reader.onabort = () => {
                reject(new Error('File reading was aborted'));
            };
            
            try {
                reader.readAsDataURL(file);
            } catch (error) {
                reject(new Error('Failed to start file reading'));
            }
        });
    }

    // Format file size
    function formatFileSize(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }

    // Add file preview to chat
    function addFilePreviewToChat(fileData) {
        const previewDiv = document.createElement('div');
        previewDiv.className = 'file-preview';
        
        previewDiv.innerHTML = `
            <div class="preview-header">
                <i class="fas ${fileData.type === 'photo' ? 'fa-image' : 
                               fileData.type === 'video' ? 'fa-video' : 
                               'fa-file'}"></i>
                <span class="preview-title">${fileData.fileName}</span>
                <button class="remove-preview" onclick="removeFilePreview(this)">
                    <i class="fas fa-times"></i>
                </button>
            </div>
        `;
        
        // Add preview to input area instead of chat messages
        const inputArea = document.querySelector('.input-area');
        const typingWrapper = document.querySelector('.typing-wrapper');
        inputArea.insertBefore(previewDiv, typingWrapper);
        
        // Enable input after adding preview
        userInput.disabled = false;
        userInput.focus();
    }

    // Function to remove file preview
    window.removeFilePreview = function(button) {
        const previewDiv = button.closest('.file-preview');
        if (previewDiv) {
            previewDiv.remove();
            // Re-enable input after removing preview
            userInput.disabled = false;
            userInput.focus();
        }
    };
});