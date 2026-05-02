import pytest
from unittest.mock import MagicMock
from use_cases.query_use_case import QueryUseCase

@pytest.fixture
def mock_cache():
    return MagicMock()

@pytest.fixture
def mock_metrics():
    return MagicMock()

@pytest.fixture
def mock_embedder():
    return MagicMock()

@pytest.fixture
def mock_vector_store():
    return MagicMock()

def test_query_use_case_cache_hit(mock_cache, mock_metrics, mock_embedder, mock_vector_store):
    # Setup
    mock_cache.get.return_value = {"context": "test context", "sources": []}
    use_case = QueryUseCase(mock_cache, mock_metrics, mock_embedder, mock_vector_store)

    # Execute
    result = use_case.execute("What is testing?")

    # Verify
    assert result["source"] == "cache"
    assert result["context"] == "test context"
    mock_metrics.inc.assert_called_with("cache_hit")
    mock_embedder.embed.assert_not_called()
    mock_vector_store.search_vector.assert_not_called()

def test_query_use_case_cache_miss(mock_cache, mock_metrics, mock_embedder, mock_vector_store):
    # Setup
    mock_cache.get.return_value = None
    mock_embedder.embed.return_value = [0.1, 0.2, 0.3]
    mock_vector_store.search_vector.return_value = [{"chunk": "answer", "metadata": {"source": "test.pdf"}, "distance": 0.1}]
    
    use_case = QueryUseCase(mock_cache, mock_metrics, mock_embedder, mock_vector_store)

    # Execute
    result = use_case.execute("What is testing?")

    # Verify
    assert result["source"] == "fresh"
    assert result["question"] == "What is testing?"
    assert "answer" in result["context"]
    mock_metrics.inc.assert_any_call("cache_miss")
    mock_embedder.embed.assert_called_once_with("What is testing?")
    mock_vector_store.search_vector.assert_called_once()
    mock_cache.set.assert_called_once()
