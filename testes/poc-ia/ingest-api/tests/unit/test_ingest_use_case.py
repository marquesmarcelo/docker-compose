import pytest
from unittest.mock import MagicMock, patch
from use_cases.ingest_use_case import IngestUseCase

@pytest.fixture
def mock_embedder():
    return MagicMock()

@pytest.fixture
def mock_vector_store():
    return MagicMock()

@patch('use_cases.ingest_use_case.split_docs')
@patch('use_cases.ingest_use_case.load_pdf')
def test_ingest_use_case(mock_load_pdf, mock_split_docs, mock_embedder, mock_vector_store):
    # Setup
    mock_load_pdf.return_value = ["doc1"]
    
    mock_chunk_1 = MagicMock()
    mock_chunk_1.page_content = "content 1"
    mock_chunk_1.metadata = {"source": "test.pdf", "page": 1}
    
    mock_split_docs.return_value = [mock_chunk_1]
    mock_embedder.embed.return_value = [0.1, 0.2]

    use_case = IngestUseCase(mock_embedder, mock_vector_store)

    # Execute
    result = use_case.execute("fake_path.pdf")

    # Verify
    assert result["status"] == "ok"
    assert result["chunks"] == 1
    mock_load_pdf.assert_called_once_with("fake_path.pdf")
    mock_split_docs.assert_called_once()
    mock_embedder.embed.assert_called_once_with("content 1")
    mock_vector_store.save_chunk.assert_called_once()
