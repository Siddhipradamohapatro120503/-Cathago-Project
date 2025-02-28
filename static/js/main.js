// Document Upload and Scanning
const uploadForm = document.getElementById('uploadForm');
if (uploadForm) {
    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const fileInput = document.getElementById('documentFile');
        const file = fileInput.files[0];
        
        if (!file) {
            alert('Please select a file');
            return;
        }
        
        const formData = new FormData();
        formData.append('file', file);
        
        try {
            const response = await fetch('/scan', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                displayResults(data);
                updateCredits(data.remaining_credits);
            } else {
                alert(data.error || 'Error scanning document');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error uploading document');
        }
    });
}

// Display scan results
function displayResults(data) {
    const resultsContainer = document.getElementById('scanResults');
    if (!resultsContainer) return;
    
    let html = '<h3>Similar Documents:</h3>';
    
    if (data.matches && data.matches.length > 0) {
        html += '<div class="matches-list">';
        data.matches.forEach(match => {
            html += `
                <div class="result-item">
                    <div class="filename">${match.filename}</div>
                    <div class="similarity">Similarity: ${(match.similarity * 100).toFixed(2)}%</div>
                </div>
            `;
        });
        html += '</div>';
    } else {
        html += '<p>No similar documents found</p>';
    }
    
    resultsContainer.innerHTML = html;
}

// Update credits display
function updateCredits(credits) {
    const creditsDisplay = document.querySelector('.credits');
    if (creditsDisplay) {
        creditsDisplay.textContent = `Credits: ${credits}`;
    }
}

// Credit Request Modal
const requestCreditsBtn = document.getElementById('requestCreditsBtn');
const creditRequestModal = document.getElementById('creditRequestModal');
const creditRequestForm = document.getElementById('creditRequestForm');

if (requestCreditsBtn) {
    requestCreditsBtn.addEventListener('click', () => {
        creditRequestModal.style.display = 'block';
    });
}

if (creditRequestForm) {
    creditRequestForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const amount = document.getElementById('creditAmount').value;
        
        try {
            const response = await fetch('/request_credits', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `amount=${amount}`
            });
            
            const data = await response.json();
            
            if (response.ok) {
                alert('Credit request submitted successfully');
                closeModal();
            } else {
                alert(data.error || 'Error submitting credit request');
            }
        } catch (error) {
            console.error('Error:', error);
            alert('Error submitting request');
        }
    });
}

// Close modal
function closeModal() {
    if (creditRequestModal) {
        creditRequestModal.style.display = 'none';
    }
}

// Admin functions
async function approveRequest(requestId) {
    try {
        const response = await fetch(`/admin/approve_credit/${requestId}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Remove the request from the table
            const row = document.querySelector(`tr[data-request-id="${requestId}"]`);
            if (row) row.remove();
            
            alert('Credit request approved');
        } else {
            alert(data.error || 'Error approving request');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error processing request');
    }
}

async function denyRequest(requestId) {
    try {
        const response = await fetch(`/admin/deny_credit/${requestId}`, {
            method: 'POST'
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Remove the request from the table
            const row = document.querySelector(`tr[data-request-id="${requestId}"]`);
            if (row) row.remove();
            
            alert('Credit request denied');
        } else {
            alert(data.error || 'Error denying request');
        }
    } catch (error) {
        console.error('Error:', error);
        alert('Error processing request');
    }
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target == creditRequestModal) {
        closeModal();
    }
}
