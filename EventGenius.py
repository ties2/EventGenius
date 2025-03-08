"""
Security Use Case Generator using RAG approach with predefined event code dataset
"""

import torch
from transformers import T5Tokenizer, T5ForConditionalGeneration
from sentence_transformers import SentenceTransformer
import numpy as np
from sklearn.metrics.pairwise import cosine_similarity
import pandas as pd
import gradio as gr
import json
import random
from datasets import EVENT_CODES, ATTACK_PATTERNS, EVENT_DESCRIPTIONS, ATTACK_CHAINS

class SecurityUseCaseGenerator:
    def __init__(self):
        # Convert event codes data to structured format
        self.event_data = self._prepare_event_data()
        
        # Create text representations for embedding
        self.event_texts = self._create_event_texts()
        
        # Load embedding model for retrieval
        self.embedding_model = SentenceTransformer('all-MiniLM-L6-v2')
        
        # Generate embeddings for all events
        self.event_embeddings = self.embedding_model.encode(self.event_texts)
        
        # Load language model for generation
        self.tokenizer = T5Tokenizer.from_pretrained("google/flan-t5-base")
        self.model = T5ForConditionalGeneration.from_pretrained("google/flan-t5-base")
        
        # Create attack pattern embeddings for semantic search
        self.attack_pattern_texts = []
        self.attack_pattern_names = []
        
        for attack_name, event_ids in ATTACK_PATTERNS.items():
            events_text = " ".join([f"Event {event_id}: {self._get_event_name(event_id)}" 
                                for event_id in event_ids])
            self.attack_pattern_texts.append(
                f"Attack pattern: {attack_name}. Related events: {events_text}"
            )
            self.attack_pattern_names.append(attack_name)
            
        self.attack_pattern_embeddings = self.embedding_model.encode(self.attack_pattern_texts)

    def _prepare_event_data(self):
        """Convert event codes list to a more usable format"""
        event_data = {}
        for event in EVENT_CODES:
            event_id = event["event_id"]
            event_data[event_id] = {
                "name": event["event_name"],
                "description": EVENT_DESCRIPTIONS.get(event_id, "")
            }
        return event_data
    
    def _create_event_texts(self):
        """Create text representations of events for embedding"""
        texts = []
        for event_id, data in self.event_data.items():
            text = f"Event ID: {event_id} - {data['name']}"
            if data['description']:
                text += f" - {data['description']}"
            texts.append(text)
        return texts
    
    def _get_event_name(self, event_id):
        """Get event name from event ID"""
        if event_id in self.event_data:
            return self.event_data[event_id]["name"]
        return "Unknown Event"
    
    def _get_event_description(self, event_id):
        """Get detailed description from event ID"""
        if event_id in self.event_data and "description" in self.event_data[event_id]:
            return self.event_data[event_id]["description"]
        return ""

    def find_similar_attack_patterns(self, query, top_k=3):
        """Find attack patterns most similar to the query"""
        query_embedding = self.embedding_model.encode([query])[0]
        
        # Calculate similarity scores
        similarities = cosine_similarity([query_embedding], self.attack_pattern_embeddings)[0]
        
        # Get indices of top_k most similar patterns
        top_indices = np.argsort(similarities)[::-1][:top_k]
        
        # Return top patterns and their scores
        top_patterns = [self.attack_pattern_names[i] for i in top_indices]
        top_scores = [similarities[i] for i in top_indices]
        
        return list(zip(top_patterns, top_scores))

    def retrieve_relevant_events(self, attack_type, top_k=7):
        """Retrieve the most relevant events for an attack type"""
        # First check if the attack type is directly in our patterns
        if attack_type in ATTACK_PATTERNS:
            events = []
            for event_id in ATTACK_PATTERNS[attack_type]:
                events.append({
                    "event_id": event_id,
                    "name": self._get_event_name(event_id),
                    "description": self._get_event_description(event_id),
                    "relevance": 1.0,
                    "do_sample":True
                })
            return events[:top_k]
        
        # If not, find similar attack patterns
        similar_patterns = self.find_similar_attack_patterns(attack_type, top_k=2)
        
        # Collect events from similar patterns
        events = []
        for pattern, score in similar_patterns:
            if pattern in ATTACK_PATTERNS:
                for event_id in ATTACK_PATTERNS[pattern]:
                    events.append({
                        "event_id": event_id,
                        "name": self._get_event_name(event_id),
                        "description": self._get_event_description(event_id),
                        "relevance": score,
                        "pattern": pattern
                    })
        
        # Deduplicate and sort by relevance
        unique_events = {}
        for event in events:
            event_id = event["event_id"]
            if event_id not in unique_events or event["relevance"] > unique_events[event_id]["relevance"]:
                unique_events[event_id] = event
                
        return list(unique_events.values())[:top_k]

    def get_attack_chain(self, attack_type):
        """Get a relevant attack chain if available"""
        # Direct match
        if attack_type in ATTACK_CHAINS:
            return ATTACK_CHAINS[attack_type]
        
        # Find similar pattern
        similar_patterns = self.find_similar_attack_patterns(attack_type, top_k=1)
        if similar_patterns and similar_patterns[0][0] in ATTACK_CHAINS:
            return ATTACK_CHAINS[similar_patterns[0][0]]
        
        # Create synthetic chain based on relevant events
        relevant_events = self.retrieve_relevant_events(attack_type, top_k=5)
        if relevant_events:
            synthetic_chain = []
            for i, event in enumerate(relevant_events):
                synthetic_chain.append({
                    "sequence": i+1,
                    "event_id": event["event_id"],
                    "context": self._generate_context_for_event(event["event_id"], attack_type)
                })
            return synthetic_chain
        
        return None

    def _generate_context_for_event(self, event_id, attack_type):
        """Generate a contextual description for an event in relation to an attack type"""
        prompt = f"Create a brief context for Windows Event ID {event_id} ({self._get_event_name(event_id)}) in a {attack_type} scenario."
        
        input_ids = self.tokenizer(prompt, return_tensors="pt", max_length=512, truncation=True).input_ids
        
        outputs = self.model.generate(
            input_ids,
            max_length=64,
            min_length=10,
            temperature=0.7
        )
        
        context = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        return context

    def generate_use_case(self, attack_type):
        """Generate a use case for the given attack type"""
        # Retrieve relevant events
        relevant_events = self.retrieve_relevant_events(attack_type)
        
        # Get attack chain
        attack_chain = self.get_attack_chain(attack_type)
        
        # Create context for prompt
        events_text = ""
        for event in relevant_events:
            events_text += f"Event ID {event['event_id']}: {event['name']}"
            if event['description']:
                events_text += f" - {event['description']}"
            events_text += "\n"
        
        chain_text = ""
        if attack_chain:
            chain_text = "Attack Chain:\n"
            for step in attack_chain:
                chain_text += f"{step['sequence']}. Event ID {step['event_id']} ({self._get_event_name(step['event_id'])}) - {step['context']}\n"
        
        # Create prompt for the language model
        prompt = f"""Generate a detailed security use case for '{attack_type}' with the following Windows Event IDs:

Relevant Event IDs:
{events_text}

{chain_text}

Create a realistic scenario for SOC analysts describing:
1. Initial compromise
2. Attack progression
3. Observable events and indicators
4. Recommended detection rules
5. Response actions"""
        
        # Generate text using the language model
        input_ids = self.tokenizer(prompt, return_tensors="pt", max_length=1024, truncation=True).input_ids
        
        outputs = self.model.generate(
            input_ids,
            max_length=768,
            min_length=200,
            num_beams=5,
            no_repeat_ngram_size=2,
            temperature=0.7
        )
        
        use_case = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Format the result
        result = {
            "attack_type": attack_type,
            "use_case": use_case,
            "relevant_events": relevant_events,
            "attack_chain": attack_chain
        }
        
        return result

def create_web_interface(generator):
    """Create a Gradio web interface for the use case generator"""
    def generate_use_case_web(attack_type):
        result = generator.generate_use_case(attack_type)
        
        # Format output
        output = f"# Security Use Case: {result['attack_type']}\n\n"
        output += result['use_case'] + "\n\n"
        
        output += "## Relevant Windows Event IDs\n"
        for event in result['relevant_events']:
            output += f"- **{event['event_id']}**: {event['name']}"
            if 'pattern' in event:
                output += f" (from {event['pattern']} pattern)"
            output += "\n"
        
        if result['attack_chain']:
            output += "\n## Attack Chain\n"
            for step in result['attack_chain']:
                output += f"{step['sequence']}. **Event ID {step['event_id']}** - {step['context']}\n"
        
        return output
    
    # Define the interface
    iface = gr.Interface(
        fn=generate_use_case_web,
        inputs=[
            gr.Textbox(label="Attack Type", placeholder="e.g., Unauthorized Access Attempt, Ransomware, Insider Threat")
        ],
        outputs=gr.Markdown(),
        title="Security Use Case Generator",
        description="Generate security use cases with Windows Event IDs for SOC analysts",
        examples=[
            ["Unauthorized Access Attempt"],
            ["Ransomware Attack"],
            ["Privilege Escalation"],
            ["Data Exfiltration"],
            ["Insider Threat"],
            ["Living Off The Land Attack"],
            ["Supply Chain Compromise"]
        ]
    )
    
    return iface

def test_and_save(generator, attack_types):
    """Test the generator with various attack types and save results"""
    results = []
    for attack in attack_types:
        print(f"Generating use case for {attack}...")
        result = generator.generate_use_case(attack)
        
        # Convert complex objects to serializable format
        serializable_result = {
            "attack_type": result["attack_type"],
            "use_case": result["use_case"],
            "relevant_events": [
                {"event_id": e["event_id"], "name": e["name"]} 
                for e in result["relevant_events"]
            ],
            "attack_chain": result["attack_chain"] if result["attack_chain"] else []
        }
        
        results.append(serializable_result)
        
        print(f"Use Case for {attack} generated successfully.")
    
    # Save results to JSON
    with open("security_use_cases.json", "w") as f:
        json.dump(results, f, indent=2)
    
    # Create a pandas DataFrame for CSV export
    df_data = []
    for result in results:
        row = {
            "attack_type": result["attack_type"],
            "use_case": result["use_case"],
            "relevant_events": ", ".join([e["event_id"] for e in result["relevant_events"]]),
        }
        df_data.append(row)
    
    df = pd.DataFrame(df_data)
    df.to_csv("security_use_cases.csv", index=False)
    
    print(f"Results saved to security_use_cases.json and security_use_cases.csv")

def main():
    # Initialize the generator
    generator = SecurityUseCaseGenerator()
    
    # Test with different attack types
    attack_types = [
        "Unauthorized Access Attempt", 
        "Malware Execution", 
        "Data Exfiltration", 
        "Privilege Escalation",
        "Ransomware Attack",
        "Insider Threat",
        "Advanced Persistent Threat"
    ]
    
    # Test the generator and save results
    test_and_save(generator, attack_types)
    
    # Launch web interface
    print("Launching web interface...")
    interface = create_web_interface(generator)
    interface.launch()

if __name__ == "__main__":
    main()