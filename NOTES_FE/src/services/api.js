import axios from "axios";

console.log("API URL:", process.env.REACT_APP_API_URL);

// Create an Axios instance
const api = axios.create({
  baseURL: `${process.env.REACT_APP_API_URL}/api`,
  headers: {
    "Content-Type": "application/json",
    Accept: "application/json",
  },
  withCredentials: true,
});

// there are two axios interceptors, request interceptors and response interceptors
// Add a request interceptor to include JWT and CSRF tokens
api.interceptors.request.use(
  async (config) => {
    const token = localStorage.getItem("JWT_TOKEN");
    //add jwt in the header  
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }

    //get from cookie first
    let csrfToken = localStorage.getItem("CSRF_TOKEN");

    //if csrf token is empty, create on from the server, fetch it and add it in the cookie
    if (!csrfToken) {
      try {
        const response = await axios.get(
          `${process.env.REACT_APP_API_URL}/api/csrf-token`,
          { withCredentials: true }
        );
        csrfToken = response.data.token;
        localStorage.setItem("CSRF_TOKEN", csrfToken);
      } catch (error) {
        console.error("Failed to fetch CSRF token", error);
      }
    }

    // if csrf is present, use it
    if (csrfToken) {
      config.headers["X-XSRF-TOKEN"] = csrfToken;
    }
    console.log("X-XSRF-TOKEN " + csrfToken);
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

export default api;
