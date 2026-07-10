#!/usr/bin/env python3
import os
import csv
import itertools
import random

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
OUTPUT_DIR = os.path.join(PROJECT_ROOT, "data", "raw", "custom")
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "synthetic_benign.csv")

def generate_greetings():
    greetings = ["Hello", "Hi", "Hey", "Greetings", "Good morning", "Good afternoon", "Good evening", "Yo", "Sup"]
    targets = ["", " there", " AI", " assistant", " friend", " everyone", " folks"]
    punctuations = ["", ".", "!", "..."]
    
    samples = []
    for g, t, p in itertools.product(greetings, targets, punctuations):
        samples.append(f"{g}{t}{p}")
    return samples

def generate_questions():
    questions = [
        "What is your name?",
        "Who are you?",
        "How are you doing today?",
        "Can you help me?",
        "Are you an AI?",
        "What can you do?",
        "Tell me about yourself.",
        "How is the weather?",
        "What time is it?",
        "Who made you?",
        "Do you have a name?",
        "Are you real?"
    ]
    return questions

def generate_common_tasks():
    templates = [
        "Please summarize the following text: {content}",
        "Write a Python script that {action}",
        "Translate the word '{content}' to French.",
        "How do I {action} in Javascript?",
        "Explain {content} to a 5 year old.",
        "Can you give me a recipe for {content}?",
        "What is the capital of {content}?",
        "I need an email template for {action}.",
        "Review this code and find bugs: {content}",
        "Generate a story about {content}."
    ]
    
    contents = ["machine learning", "photosynthesis", "Paris", "chocolate cake", "a brave knight", "React.js", "data structures"]
    actions = ["sort an array", "connect to a database", "request a day off", "handle errors", "make an API call"]
    
    samples = []
    for t in templates:
        for c in contents:
            if "{content}" in t:
                samples.append(t.replace("{content}", c))
        for a in actions:
            if "{action}" in t:
                samples.append(t.replace("{action}", a))
    return samples

def generate_edge_cases():
    return [
        ".", "!", "?", "...", "???", "---", "okay", "yes", "no", "ok", "sure",
        "thanks", "thank you", "bye", "goodbye", "see ya", "k", "cool",
        "wow", "awesome", "great", "nice", "123", "a", "b", "c", "wtf", "hmm", "ugh"
    ]

def main():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    
    all_benign = []
    all_benign.extend(generate_greetings())
    all_benign.extend(generate_questions())
    all_benign.extend(generate_common_tasks())
    all_benign.extend(generate_edge_cases())
    
    # Randomly shuffle
    random.seed(42)
    random.shuffle(all_benign)
    
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        for text in all_benign:
            writer.writerow([text, 0])  # 0 is benign

    print(f"Generated {len(all_benign)} synthetic benign examples and saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
