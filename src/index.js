import fs from "fs";
import path from "path";
import crypto from "crypto";
import dotenv from "dotenv";
import JSZip from "jszip";

dotenv.config();

const users_url = "https://dunkbin.com/export/users";
const username = process.env.DUNKBIN_USER;
const password = process.env.DUNKBIN_PASSWORD;
const twitchClientId = process.env.TWITCH_CLIENT_ID;
const twitchAccessToken = process.env.TWITCH_ACCESS_TOKEN;

if (!username || !password || !twitchClientId || !twitchAccessToken) {
  throw new Error("Missing required environment variables");
}

const headers = new Headers();
headers.set("Authorization", "Basic " + Buffer.from(`${username}:${password}`).toString("base64"));

const pfpDir = "./public/users_pfps/";
const hashCacheFile = "./public/hash_cache.json";
const pfpMappingFile = "./public/pfp_map.json";

// Ensure directories exist
if (!fs.existsSync(pfpDir)) {
  fs.mkdirSync(pfpDir, { recursive: true });
}

// Load existing hash cache
let hashCache = new Map();
try {
  if (fs.existsSync(hashCacheFile)) {
    const cacheData = JSON.parse(fs.readFileSync(hashCacheFile, "utf8"));
    hashCache = new Map(Object.entries(cacheData));
  }
} catch (error) {
  console.error("Failed to load hash cache:", error.message);
}

// Save hash cache
function saveHashCache() {
  try {
    const cacheData = Object.fromEntries(hashCache);
    fs.writeFileSync(hashCacheFile, JSON.stringify(cacheData, null, 2));
  } catch (error) {
    console.error("Failed to save hash cache:", error.message);
  }
}

// Save PFP mapping JSON
function savePfpMapping(userPfpMap) {
  try {
    fs.writeFileSync(pfpMappingFile, JSON.stringify(userPfpMap, null, 2));
    console.log(`Saved PFP mapping to ${pfpMappingFile}`);
  } catch (error) {
    console.error("Failed to save PFP mapping:", error.message);
  }
}

const zip = new JSZip();
zip.file("pfp_map.json", fs.readFileSync(pfpMappingFile));
const zipContent = await zip.generateAsync({
  type: "nodebuffer",
  compression: "DEFLATE",
  compressionOptions: { level: 9 },
});

fs.writeFileSync("./public/pfp_map.zip", zipContent);
fs.unlinkSync(pfpMappingFile);

async function fetchData(url) {
  const maxRetries = 3;
  let lastError;

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const response = await fetch(url, { method: "GET", headers });

      if (!response.ok) {
        // Handle different HTTP status codes
        if (response.status >= 500) {
          throw new Error(`Server error: ${response.status} - ${response.statusText}`);
        } else if (response.status === 429) {
          if (attempt < maxRetries) {
            const retryAfter = response.headers.get("retry-after") || 60;
            console.warn(
              `Rate limited fetching ${url}. Attempt ${attempt}/${maxRetries}. Waiting ${retryAfter} seconds...`
            );
            await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
            continue;
          } else {
            throw new Error(`Rate limit exceeded after ${maxRetries} attempts`);
          }
        } else if (response.status >= 400) {
          throw new Error(`Client error: ${response.status} - ${response.statusText}`);
        }
      }

      return await response.json();
    } catch (error) {
      lastError = error;

      if (attempt === maxRetries) {
        throw new Error(`Failed to fetch ${url} after ${maxRetries} attempts: ${error.message}`);
      }

      // Exponential backoff for retries (but not for rate limiting, that's handled above)
      if (!error.message.includes("Rate limit")) {
        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 10000);
        console.warn(`Attempt ${attempt}/${maxRetries} failed for ${url}: ${error.message}. Retrying in ${delay}ms...`);
        await new Promise((resolve) => setTimeout(resolve, delay));
      }
    }
  }
}

async function fetchTwitchToken() {
  // Refresh Twitch OAuth token using client credentials
  const params = new URLSearchParams();
  params.append("client_id", twitchClientId);
  params.append("client_secret", process.env.TWITCH_CLIENT_SECRET);
  params.append("grant_type", "client_credentials");

  const response = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!response.ok) throw new Error("Failed to refresh Twitch token: " + response.status);
  const data = await response.json();
  return data.access_token;
}

// Global token management
let currentTwitchToken = twitchAccessToken;
let tokenRefreshPromise = null;

async function getValidTwitchToken() {
  // If there's already a refresh in progress, wait for it
  if (tokenRefreshPromise) {
    console.log("Token refresh already in progress, waiting...");
    return await tokenRefreshPromise;
  }

  try {
    // Try refresh token first
    const refreshToken = process.env.TWITCH_REFRESH_TOKEN;
    if (refreshToken) {
      tokenRefreshPromise = fetchTwitchTokenWithRefresh(refreshToken);
      currentTwitchToken = await tokenRefreshPromise;
      console.log("Successfully refreshed token using refresh_token");
    } else {
      // Fallback to client credentials
      console.log("No refresh token available, using client credentials flow");
      tokenRefreshPromise = fetchTwitchToken();
      currentTwitchToken = await tokenRefreshPromise;
      updateEnvAccessToken(currentTwitchToken);
    }

    tokenRefreshPromise = null;
    return currentTwitchToken;
  } catch (error) {
    tokenRefreshPromise = null;
    console.error("Failed to refresh token:", error.message);
    throw error;
  }
}

function updateEnvAccessToken(newToken) {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return;
  let envContent = fs.readFileSync(envPath, "utf8");
  if (envContent.includes("TWITCH_ACCESS_TOKEN=")) {
    envContent = envContent.replace(/TWITCH_ACCESS_TOKEN=.*/g, `TWITCH_ACCESS_TOKEN=${newToken}`);
  } else {
    envContent += `\nTWITCH_ACCESS_TOKEN=${newToken}`;
  }
  fs.writeFileSync(envPath, envContent);
  console.log("Updated .env with new TWITCH_ACCESS_TOKEN");
}

async function fetchTwitchTokenWithRefresh(refreshToken) {
  // Refresh Twitch OAuth token using refresh_token grant
  const params = new URLSearchParams();
  params.append("client_id", twitchClientId);
  params.append("client_secret", process.env.TWITCH_CLIENT_SECRET);
  params.append("grant_type", "refresh_token");
  params.append("refresh_token", refreshToken);

  const response = await fetch("https://id.twitch.tv/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: params.toString(),
  });
  if (!response.ok) {
    throw new Error(`Failed to refresh Twitch token with refresh_token: ${response.status} - ${await response.text()}`);
  }
  const data = await response.json();
  if (data.access_token) {
    updateEnvAccessToken(data.access_token);
    // Also update refresh token if provided
    if (data.refresh_token) {
      updateEnvRefreshToken(data.refresh_token);
    }
  }
  return data.access_token;
}

function updateEnvRefreshToken(newRefreshToken) {
  const envPath = path.resolve(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) return;
  let envContent = fs.readFileSync(envPath, "utf8");
  if (envContent.includes("TWITCH_REFRESH_TOKEN=")) {
    envContent = envContent.replace(/TWITCH_REFRESH_TOKEN=.*/g, `TWITCH_REFRESH_TOKEN=${newRefreshToken}`);
  } else {
    envContent += `\nTWITCH_REFRESH_TOKEN=${newRefreshToken}`;
  }
  fs.writeFileSync(envPath, envContent);
  console.log("Updated .env with new TWITCH_REFRESH_TOKEN");
}

async function fetchTwitchUsers(usernames, token) {
  const chunks = [];
  for (let i = 0; i < usernames.length; i += 100) {
    chunks.push(usernames.slice(i, i + 100));
  }

  const allUsers = [];
  console.log(`Fetching Twitch data for ${usernames.length} users in ${chunks.length} chunks`);

  for (let i = 0; i < chunks.length; i++) {
    const chunk = chunks[i];
    const params = new URLSearchParams();
    chunk.forEach((username) => params.append("login", username));

    let response;
    let retryCount = 0;
    const maxRetries = 3;

    while (retryCount <= maxRetries) {
      try {
        response = await fetch(`https://api.twitch.tv/helix/users?${params}`, {
          headers: {
            "Client-ID": twitchClientId,
            Authorization: `Bearer ${currentTwitchToken}`,
          },
        });

        // Handle auth errors (400, 401)
        if (response.status === 401 || response.status === 400) {
          if (retryCount < maxRetries) {
            console.warn(
              `Auth error ${response.status} on chunk ${i + 1}, attempt ${retryCount + 1}/${
                maxRetries + 1
              }, refreshing token...`
            );
            currentTwitchToken = await getValidTwitchToken();
            retryCount++;
            continue;
          } else {
            console.error(`Failed to authenticate after ${maxRetries + 1} attempts on chunk ${i + 1}`);
            break;
          }
        }

        // Handle rate limiting
        if (response.status === 429) {
          if (retryCount < maxRetries) {
            const retryAfter = response.headers.get("retry-after") || 60;
            console.warn(
              `Rate limited on chunk ${i + 1}, attempt ${retryCount + 1}/${
                maxRetries + 1
              }. Waiting ${retryAfter} seconds...`
            );
            await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
            retryCount++;
            continue;
          } else {
            console.error(`Rate limit exceeded after ${maxRetries + 1} attempts on chunk ${i + 1}`);
            break;
          }
        }

        // Handle server errors
        if (response.status >= 500) {
          if (retryCount < maxRetries) {
            console.warn(`Server error ${response.status} on chunk ${i + 1}, retrying...`);
            retryCount++;
            await new Promise((resolve) => setTimeout(resolve, 2000 * retryCount));
            continue;
          }
        }

        if (!response.ok) {
          console.error(`Failed to fetch Twitch users chunk ${i + 1}: ${response.status} - ${response.statusText}`);
          break;
        }

        const data = await response.json();
        console.log(`Chunk ${i + 1}: Retrieved ${data.data.length} Twitch users`);
        allUsers.push(...data.data);
        break; // Success, exit retry loop
      } catch (error) {
        if (retryCount < maxRetries) {
          console.warn(
            `Network error on chunk ${i + 1}, attempt ${retryCount + 1}/${maxRetries + 1}: ${error.message}`
          );
          retryCount++;
          await new Promise((resolve) => setTimeout(resolve, 1000 * retryCount)); // Exponential backoff
        } else {
          console.error(`Error fetching chunk ${i + 1} after ${maxRetries + 1} attempts: ${error.message}`);
          break;
        }
      }
    }

    if (i < chunks.length - 1) {
      await new Promise((resolve) => setTimeout(resolve, 200)); // Slightly longer delay
    }
  }

  console.log(`Successfully fetched ${allUsers.length}/${usernames.length} Twitch users`);
  return allUsers;
}

async function downloadProfilePicture(userId, profileImageUrl) {
  try {
    console.log(`Attempting to download profile picture for user ${userId} from ${profileImageUrl}`);

    const fetchWithTimeout = async (url, options = {}, timeoutMs = 15000) => {
      console.log(`Fetching URL with timeout: ${url}`);

      // Check if this is a Twitch API request that might need auth
      const isTwitchAPI = url.includes("api.twitch.tv");
      if (isTwitchAPI && !options.headers) {
        options.headers = {};
      }
      if (isTwitchAPI) {
        options.headers["Client-ID"] = twitchClientId;
        options.headers["Authorization"] = `Bearer ${currentTwitchToken}`;
      }

      let retryCount = 0;
      const maxRetries = 3;

      while (retryCount <= maxRetries) {
        try {
          const controller = new AbortController();
          const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

          const response = await fetch(url, {
            ...options,
            signal: controller.signal,
          });

          clearTimeout(timeoutId);

          // Handle auth errors for Twitch API requests
          if (isTwitchAPI && (response.status === 401 || response.status === 400)) {
            if (retryCount < maxRetries) {
              console.warn(
                `Auth error ${response.status} downloading ${url}, attempt ${retryCount + 1}/${
                  maxRetries + 1
                }, refreshing token...`
              );
              currentTwitchToken = await getValidTwitchToken();
              options.headers["Authorization"] = `Bearer ${currentTwitchToken}`;
              retryCount++;
              continue;
            }
          }

          // Handle rate limiting
          if (response.status === 429) {
            if (retryCount < maxRetries) {
              const retryAfter = response.headers.get("retry-after") || 60;
              console.warn(
                `Rate limited downloading ${url}, attempt ${retryCount + 1}/${
                  maxRetries + 1
                }. Waiting ${retryAfter} seconds...`
              );
              await new Promise((resolve) => setTimeout(resolve, retryAfter * 1000));
              retryCount++;
              continue;
            } else {
              throw new Error(`Rate limit exceeded after ${maxRetries + 1} attempts`);
            }
          }

          // Handle server errors
          if (response.status >= 500 && retryCount < maxRetries) {
            console.warn(`Server error ${response.status} downloading ${url}, retrying...`);
            retryCount++;
            await new Promise((resolve) => setTimeout(resolve, 2000 * retryCount));
            continue;
          }

          return response;
        } catch (error) {
          if (error.name === "AbortError") {
            console.warn(`Request timeout for ${url}`);
          }

          if (
            retryCount < maxRetries &&
            (error.name === "AbortError" ||
              error.message.includes("timeout") ||
              error.message.includes("fetch") ||
              error.message.includes("network"))
          ) {
            console.warn(
              `Network error downloading ${url}, attempt ${retryCount + 1}/${maxRetries + 1}: ${error.message}`
            );
            retryCount++;
            await new Promise((resolve) => setTimeout(resolve, 1000 * retryCount));
            continue;
          }
          throw error;
        }
      }
    };

    userId = String(userId);
    const possibleExtensions = ["png", "jpg", "jpeg", "gif", "webp"];
    let existingFile = null;
    let existingExtension = null;
    const existingHash = hashCache.get(userId);

    // Check for existing file
    for (const ext of possibleExtensions) {
      const checkPath = path.join(pfpDir, `${userId}.${ext}`);
      if (fs.existsSync(checkPath)) {
        existingFile = checkPath;
        existingExtension = ext;
        break;
      }
    }

    // Determine extension from URL or existing file
    let extension = existingExtension || "png";
    try {
      const url = new URL(profileImageUrl);
      const pathname = url.pathname;
      const urlExtension = path.extname(pathname).toLowerCase();
      if (urlExtension && urlExtension.length > 1) {
        extension = urlExtension.substring(1); // Remove the dot
        if (extension === "jpeg") extension = "jpg";
        // Validate extension
        if (!possibleExtensions.includes(extension)) {
          extension = "png"; // Default fallback
        }
      }
    } catch (error) {
      console.warn(`Invalid URL format for user ${userId}: ${profileImageUrl}`);
      // Keep default extension
    }

    // Download the image
    console.log(`Initiating download for ${profileImageUrl}`);
    const response = await fetchWithTimeout(profileImageUrl, {
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        Accept: "image/*,*/*;q=0.8",
      },
    });

    console.log(`Download response status: ${response.status}`);
    if (!response.ok) {
      console.error(`Failed to download image: ${response.status} ${response.statusText}`);
      if (existingFile) {
        console.log(`Using existing file: ${existingFile}`);
        return { success: true, filename: path.basename(existingFile), cached: true };
      }
      return { success: false, error: `HTTP ${response.status}: ${response.statusText}` };
    }

    // Validate content type
    const contentType = response.headers.get("content-type");
    if (contentType && !contentType.startsWith("image/")) {
      console.warn(`Unexpected content type for ${userId}: ${contentType}`);
      if (existingFile) {
        return { success: true, filename: path.basename(existingFile), cached: true };
      }
      return { success: false, error: `Invalid content type: ${contentType}` };
    }

    const buffer = await response.arrayBuffer();
    const imageBuffer = Buffer.from(buffer);

    // Verify we have actual image data
    if (imageBuffer.length === 0) {
      console.error(`Downloaded image is empty for user ${userId}`);
      if (existingFile) {
        return { success: true, filename: path.basename(existingFile), cached: true };
      }
      return { success: false, error: "Empty image data" };
    }

    // Basic image validation (check for common image signatures)
    if (!isValidImageBuffer(imageBuffer)) {
      console.warn(`Downloaded data doesn't appear to be a valid image for user ${userId}`);
      if (existingFile) {
        return { success: true, filename: path.basename(existingFile), cached: true };
      }
      return { success: false, error: "Invalid image format" };
    }

    const newHash = crypto.createHash("sha1").update(imageBuffer).digest("hex");

    // Check if image changed
    if (existingFile && existingHash === newHash) {
      console.log(`Image unchanged for user ${userId}, using cached version`);
      return { success: true, filename: path.basename(existingFile), cached: true };
    }

    // Save the image with explicit error handling
    const filename = `${userId}.${extension}`;
    const filepath = path.join(pfpDir, filename);

    // Remove old file if extension changed
    if (existingFile && existingFile !== filepath) {
      try {
        fs.unlinkSync(existingFile);
        console.log(`Removed old file: ${existingFile}`);
      } catch (unlinkError) {
        console.warn(`Failed to remove old file ${existingFile}:`, unlinkError.message);
      }
    }

    // Write the file with proper error handling
    try {
      fs.writeFileSync(filepath, imageBuffer);
      console.log(`Successfully saved image: ${filepath} (${imageBuffer.length} bytes)`);

      // Verify the file was actually written
      if (!fs.existsSync(filepath)) {
        throw new Error("File not found after write operation");
      }

      const savedSize = fs.statSync(filepath).size;
      if (savedSize !== imageBuffer.length) {
        throw new Error(`File size mismatch: expected ${imageBuffer.length}, got ${savedSize}`);
      }

      hashCache.set(userId, newHash);

      return {
        success: true,
        filename: path.basename(filepath),
        cached: false,
        size: savedSize,
      };
    } catch (writeError) {
      console.error(`Failed to write file ${filepath}:`, writeError.message);
      if (existingFile) {
        return { success: true, filename: path.basename(existingFile), cached: true };
      }
      return { success: false, error: writeError.message };
    }
  } catch (error) {
    console.error(`Error downloading profile picture for user ${userId}:`, error.message);
    // Fallback to existing file on any error
    const possibleExtensions = ["png", "jpg", "jpeg", "gif", "webp"];
    for (const ext of possibleExtensions) {
      const checkPath = path.join(pfpDir, `${String(userId)}.${ext}`);
      if (fs.existsSync(checkPath)) {
        return { success: true, filename: path.basename(checkPath), cached: true };
      }
    }
    return { success: false, error: error.message };
  }
}

// Basic image validation function
function isValidImageBuffer(buffer) {
  if (buffer.length < 8) return false;

  // Check for common image file signatures
  const signatures = [
    [0x89, 0x50, 0x4e, 0x47], // PNG
    [0xff, 0xd8, 0xff], // JPEG
    [0x47, 0x49, 0x46], // GIF
    [0x52, 0x49, 0x46, 0x46], // WEBP (RIFF)
  ];

  return signatures.some((sig) => {
    for (let i = 0; i < sig.length; i++) {
      if (buffer[i] !== sig[i]) return false;
    }
    return true;
  });
}

async function updateProfilePictures() {
  try {
    console.log("Starting profile picture update process");
    console.log("=====================================");

    // Verify no_image_available.png exists
    const noImagePath = path.join(pfpDir, "no_image_available.png");
    if (!fs.existsSync(noImagePath)) {
      console.error("ERROR: no_image_available.png not found in users_pfps directory!");
      console.error("Please ensure this file exists before running the script.");
      throw new Error("Missing no_image_available.png file");
    }

    // Fetch users from DunkBin
    console.log("Fetching users from DunkBin...");
    const users = await fetchData(users_url);
    console.log(`Found ${users.length} users`);

    // Fetch Twitch user data
    const usernames = users.map((user) => user.login).filter(Boolean);
    const twitchUsers = await fetchTwitchUsers(usernames, currentTwitchToken);

    // Create Twitch profile image map
    const twitchProfileImages = new Map();
    twitchUsers.forEach((user) => {
      if (user.login && user.profile_image_url) {
        twitchProfileImages.set(user.login.toLowerCase(), user.profile_image_url);
      }
    });

    // Process profile pictures
    console.log("Processing profile pictures...");
    const validUsers = users.filter((user) => {
      const hasImage = user.login && twitchProfileImages.get(user.login.toLowerCase());
      if (!hasImage) {
        console.log(`No Twitch profile image found for user: ${user.login || "unknown"} (ID: ${user.id})`);
      }
      return hasImage;
    });

    console.log(`Found ${validUsers.length} valid users with Twitch profile images`);

    let successCount = 0;
    let errorCount = 0;
    let cacheHitCount = 0;
    let skippedCount = users.length - validUsers.length;

    // Initialize the user PFP mapping
    const userPfpMapping = {
      metadata: {
        generated: new Date().toISOString(),
        totalUsers: users.length,
        usersWithPfp: 0,
        usersWithoutPfp: 0,
        errors: 0,
      },
      users: {},
    };

    const concurrency = 99;
    for (let i = 0; i < validUsers.length; i += concurrency) {
      const chunk = validUsers.slice(i, i + concurrency);
      const downloads = chunk.map(async (user) => {
        const profileImageUrl = twitchProfileImages.get(user.login.toLowerCase());

        try {
          const result = await downloadProfilePicture(user.id, profileImageUrl);

          // Add to mapping regardless of success/failure
          userPfpMapping.users[user.id] = {
            username: user.login,
            display_name: user.display_name || user.login,
            pfp_filename: result.success ? result.filename : "no_image_available.png",
            has_custom_pfp: result.success,
            cached: result.cached || false,
            twitch_profile_url: profileImageUrl,
            file_size: result.size || null,
            last_updated: new Date().toISOString(),
          };

          if (result.success) {
            successCount++;
            if (result.cached) {
              cacheHitCount++;
            }
            console.log(
              `✓ User ${user.id} (${user.login}): ${result.filename} ${result.cached ? "(cached)" : "(downloaded)"}`
            );
          } else {
            errorCount++;
            console.error(`✗ User ${user.id} (${user.login}): ${result.error}`);
          }
        } catch (error) {
          errorCount++;
          console.error(`✗ User ${user.id} (${user.login}): ${error.message}`);

          // Add failed user to mapping
          userPfpMapping.users[user.id] = {
            username: user.login,
            display_name: user.display_name || user.login,
            pfp_filename: "no_image_available.png",
            has_custom_pfp: false,
            cached: false,
            twitch_profile_url: profileImageUrl,
            file_size: null,
            last_updated: new Date().toISOString(),
            error: error.message,
          };
        }
      });

      await Promise.all(downloads);

      // Longer delay between chunks to be more respectful
      if (i + concurrency < validUsers.length) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
      }
    }

    // Add users without Twitch profile images to the mapping
    const usersWithoutImages = users.filter((user) => !validUsers.includes(user));
    usersWithoutImages.forEach((user) => {
      userPfpMapping.users[user.id] = {
        username: user.login || "unknown",
        display_name: user.display_name || user.login || "unknown",
        pfp_filename: "no_image_available.png",
        has_custom_pfp: false,
        cached: false,
        twitch_profile_url: null,
        file_size: null,
        last_updated: new Date().toISOString(),
        reason: "No Twitch profile image available",
      };
    });

    // Update metadata
    userPfpMapping.metadata.usersWithPfp = successCount;
    userPfpMapping.metadata.usersWithoutPfp = skippedCount + errorCount;
    userPfpMapping.metadata.errors = errorCount;

    // Save the hash cache and PFP mapping
    saveHashCache();
    savePfpMapping(userPfpMapping);

    console.log("\n=====================================");
    console.log("Profile picture update completed!");
    console.log(`Total users: ${users.length}`);
    console.log(`Successfully processed: ${successCount}`);
    console.log(`Cache hits: ${cacheHitCount}`);
    console.log(`Errors: ${errorCount}`);
    console.log(`Skipped (no Twitch image): ${skippedCount}`);
    console.log(`PFP mapping saved to: ${pfpMappingFile}`);
    console.log("=====================================");
    process.exit(0);
  } catch (error) {
    console.error("Fatal error in updateProfilePictures:", error.message);
    console.error("Stack trace:", error.stack);
    process.exit(1);
  }
}

// Handle uncaught exceptions
process.on("uncaughtException", (error) => {
  console.error("Uncaught Exception:", error);
  process.exit(1);
});

process.on("unhandledRejection", (reason, promise) => {
  console.error("Unhandled Rejection at:", promise, "reason:", reason);
  process.exit(1);
});

// Run the update process
updateProfilePictures().catch(console.error);
