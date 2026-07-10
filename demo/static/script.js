document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('prompt-input');
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultSection = document.getElementById('result-section');
    const loading = document.getElementById('loading');
    
    const badge = document.getElementById('prediction-badge');
    const confidenceFill = document.getElementById('confidence-fill');
    const confidenceText = document.getElementById('confidence-text');

    analyzeBtn.addEventListener('click', async () => {
        const text = input.value.trim();
        if (!text) return;

        // Reset UI
        analyzeBtn.disabled = true;
        resultSection.classList.add('hidden');
        loading.classList.remove('hidden');
        confidenceFill.style.width = '0%';
        badge.className = 'badge';
        confidenceFill.className = 'progress-fill';

        try {
            const response = await fetch('/predict', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ text })
            });

            if (!response.ok) {
                throw new Error('Prediction failed');
            }

            const data = await response.json();
            displayResult(data);
        } catch (error) {
            console.error('Error:', error);
            alert('Failed to analyze prompt. Ensure the backend is running.');
        } finally {
            analyzeBtn.disabled = false;
            loading.classList.add('hidden');
        }
    });

    function displayResult(data) {
        const isInjection = data.prediction === 'INJECTION';
        const confidencePct = (data.confidence * 100).toFixed(2);

        badge.textContent = isInjection ? 'INJECTION DETECTED' : 'BENIGN';
        badge.classList.add(isInjection ? 'danger' : 'safe');
        
        confidenceFill.classList.add(isInjection ? 'danger' : 'safe');
        confidenceText.textContent = `${confidencePct}%`;
        
        // Render SHAP
        const shapTextDiv = document.getElementById('shap-text');
        shapTextDiv.innerHTML = '';
        if (data.attributions) {
            data.attributions.forEach(attr => {
                const span = document.createElement('span');
                // The value is positive if it pushes towards the predicted class
                // If it pushes towards INJECTION, make it red, if BENIGN, make it green.
                // Wait, SHAP values are relative to the predicted class!
                // If the prediction is INJECTION, a positive value means it pushed towards INJECTION.
                // If the prediction is BENIGN, a positive value means it pushed towards BENIGN.
                
                let val = attr.value;
                let colorClass = '';
                let intensity = Math.min(Math.abs(val) * 2, 1); // Scale intensity

                if (isInjection) {
                    if (val > 0) colorClass = `rgba(239, 68, 68, ${intensity})`; // pushed to injection
                    else colorClass = `rgba(34, 197, 94, ${intensity})`; // pushed to benign
                } else {
                    if (val > 0) colorClass = `rgba(34, 197, 94, ${intensity})`; // pushed to benign
                    else colorClass = `rgba(239, 68, 68, ${intensity})`; // pushed to injection
                }

                span.className = 'shap-word';
                span.style.backgroundColor = colorClass;
                span.textContent = attr.word;
                shapTextDiv.appendChild(span);
            });
        }
        
        resultSection.classList.remove('hidden');
        
        // Slight delay for animation
        setTimeout(() => {
            confidenceFill.style.width = `${confidencePct}%`;
        }, 50);
    }
});
