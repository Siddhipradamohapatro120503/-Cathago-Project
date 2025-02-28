import os
from typing import List, Dict, Tuple
import numpy as np
from dotenv import load_dotenv
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

# Load environment variables
load_dotenv()

class DeepSeekMatcher:
    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=1000, stop_words='english')
        self.embedding_cache = {}

    def get_document_embedding(self, text: str) -> np.ndarray:
        """Get embedding for a document using TF-IDF"""
        if text in self.embedding_cache:
            return self.embedding_cache[text]

        try:
            # Use TF-IDF for document embedding
            embedding = self.vectorizer.fit_transform([text]).toarray()[0]
            self.embedding_cache[text] = embedding
            return embedding
        except Exception as e:
            print(f"Error getting embedding: {e}")
            return None

    def compute_similarity(self, doc1: str, doc2: str) -> float:
        """Compute similarity between two documents"""
        try:
            # Use TF-IDF and cosine similarity
            tfidf_matrix = self.vectorizer.fit_transform([doc1, doc2])
            similarity = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0]
            return float(similarity)
        except Exception as e:
            print(f"Error computing similarity: {e}")
            return 0.0

    def find_similar_documents(self, query_doc: str, documents: List[Dict]) -> List[Tuple[Dict, float]]:
        """Find similar documents to the query document"""
        try:
            # Extract content from documents
            doc_contents = [query_doc] + [doc['content'] for doc in documents]
            
            # Calculate TF-IDF matrix
            tfidf_matrix = self.vectorizer.fit_transform(doc_contents)
            
            # Calculate similarity between query and all documents
            similarities = cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:])[0]
            
            # Pair documents with their similarity scores
            doc_similarities = list(zip(documents, similarities))
            
            # Sort by similarity score in descending order
            doc_similarities.sort(key=lambda x: x[1], reverse=True)
            return doc_similarities
        except Exception as e:
            print(f"Error finding similar documents: {e}")
            return []

    def analyze_document_content(self, text: str) -> Dict:
        """Analyze document content using basic NLP techniques"""
        try:
            # Basic document analysis
            words = text.split()
            word_count = len(words)
            unique_words = len(set(words))
            avg_word_length = sum(len(word) for word in words) / word_count if word_count > 0 else 0
            
            # Get important terms using TF-IDF
            tfidf = self.vectorizer.fit_transform([text])
            feature_names = self.vectorizer.get_feature_names_out()
            important_terms = [
                feature_names[i] 
                for i in tfidf.toarray()[0].argsort()[-5:][::-1]
            ]
            
            analysis = {
                'content_analysis': {
                    'summary': f"Document contains {word_count} words with {unique_words} unique terms.",
                    'important_terms': important_terms
                },
                'metrics': {
                    'word_count': word_count,
                    'unique_words': unique_words,
                    'avg_word_length': round(avg_word_length, 2),
                    'complexity_score': self._estimate_complexity(text)
                }
            }
            return analysis
        except Exception as e:
            print(f"Error analyzing document: {e}")
            return self._get_fallback_analysis(text)

    def _get_fallback_analysis(self, text: str) -> Dict:
        """Provide basic analysis when primary analysis fails"""
        try:
            word_count = len(text.split())
            return {
                'content_analysis': {
                    'summary': "Basic analysis only",
                    'important_terms': []
                },
                'metrics': {
                    'word_count': word_count,
                    'unique_words': len(set(text.split())),
                    'avg_word_length': sum(len(word) for word in text.split()) / word_count if word_count > 0 else 0,
                    'complexity_score': self._estimate_complexity(text)
                }
            }
        except Exception:
            return {
                'content_analysis': {
                    'summary': "Analysis failed",
                    'important_terms': []
                },
                'metrics': {
                    'word_count': 0,
                    'unique_words': 0,
                    'avg_word_length': 0,
                    'complexity_score': 0
                }
            }

    def _estimate_complexity(self, text: str) -> float:
        """Estimate document complexity based on various metrics"""
        try:
            words = text.split()
            if not words:
                return 0.0
                
            # Calculate metrics
            unique_words = len(set(words))
            total_words = len(words)
            avg_word_length = sum(len(word) for word in words) / total_words
            word_diversity = unique_words / total_words
            
            # Combine metrics into a complexity score (0-1)
            complexity = (word_diversity * 0.5 + (avg_word_length / 10) * 0.5)
            return round(min(complexity, 1.0), 2)
        except Exception:
            return 0.0
