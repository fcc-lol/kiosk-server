export const editUrl = async (data) => {
  try {
    const apiKey = getApiKeyFromUrl();
    if (!apiKey) {
      throw new Error("API key is required");
    }
    const { oldId, ...updateData } = data;
    const response = await fetch(`${API_BASE_URL}/edit-url`, {
      method: "PUT",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        id: oldId, // This is the correct field name that the server expects
        ...updateData,
        fccApiKey: apiKey
      })
    });
    await handleError(response);
    return response.json();
  } catch (error) {
    console.error("Error editing URL:", error);
    throw error;
  }
};
