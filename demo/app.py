import os
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

app = Flask(__name__, static_folder='static', static_url_path='')
CORS(app)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MODEL_DIR = os.path.join(PROJECT_ROOT, "models", "prompt-injection-distilbert", "best")

print("Loading Model...")
if os.path.exists(MODEL_DIR):
    tokenizer = AutoTokenizer.from_pretrained(MODEL_DIR)
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_DIR)
    print("Model loaded successfully.")
else:
    print(f"Warning: Model not found at {MODEL_DIR}")
    tokenizer = None
    model = None

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/predict', methods=['POST'])
def predict():
    if model is None or tokenizer is None:
        return jsonify({"error": "Model not loaded"}), 500

    data = request.json
    if not data or 'text' not in data:
        return jsonify({"error": "No text provided"}), 400

    text = data['text']
    inputs = tokenizer(text, return_tensors="pt", truncation=True, max_length=512)
    
    with torch.no_grad():
        outputs = model(**inputs)
    
    logits = outputs.logits
    predicted_class_id = logits.argmax().item()
    predicted_label = model.config.id2label[predicted_class_id]
    
    probs = torch.softmax(logits, dim=-1)
    confidence = probs[0][predicted_class_id].item()
    
    # SHAP Explainability
    attributions = []
    try:
        from transformers import pipeline
        import shap
        classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, top_k=None)
        explainer = shap.Explainer(classifier)
        shap_values = explainer([text])
        
        pipeline_out = classifier(text)[0]
        class_idx = next(i for i, v in enumerate(pipeline_out) if v['label'] == predicted_label)
        
        words = shap_values.data[0]
        vals = shap_values.values[0][:, class_idx]
        
        for w, v in zip(words, vals):
            attributions.append({"word": w, "value": float(v)})
    except Exception as e:
        print(f"SHAP error: {e}")
    
    return jsonify({
        "prediction": predicted_label.upper(),
        "confidence": confidence,
        "text": text,
        "attributions": attributions
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
