from langchain_text_splitters import RecursiveCharacterTextSplitter

splitter = RecursiveCharacterTextSplitter(
    chunk_size=1200,
    chunk_overlap=200,
    separators=[
        "\n\n",
        "\n",
        ". ",
        "; ",
        " ",
        ""
    ]
)

def split_docs(docs):
    return splitter.split_documents(docs)
