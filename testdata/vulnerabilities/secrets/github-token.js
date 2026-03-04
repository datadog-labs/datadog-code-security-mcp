/**
 * Hardcoded GitHub credentials - SECURITY VULNERABILITY
 * Example secrets for E2E testing of secrets detection
 */

// VULNERABLE: Hardcoded GitHub Personal Access Token (classic format)
const GITHUB_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

// VULNERABLE: GitHub Personal Access Token (fine-grained format)
const GITHUB_FINE_GRAINED_TOKEN = "github_pat_11AABCDEFGH1234567890_abcdefghijklmnopqrstuvwxyz123456789";

// VULNERABLE: GitHub OAuth token
const GITHUB_OAUTH_TOKEN = "gho_abcdefghijklmnopqrstuvwxyz1234567890AB";

// VULNERABLE: GitHub App installation token
const GITHUB_APP_TOKEN = "ghs_1234567890abcdefghijklmnopqrstuvwxyzAB";

// VULNERABLE: GitHub refresh token
const GITHUB_REFRESH_TOKEN = "ghr_1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/**
 * VULNERABLE: GitHub API client with hardcoded token
 */
class GitHubClient {
    constructor() {
        // VULNERABLE: Hardcoded token in constructor
        this.token = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890";
        this.apiUrl = "https://api.github.com";
    }

    async fetchRepositories(username) {
        // VULNERABLE: Token used in Authorization header
        const response = await fetch(`${this.apiUrl}/users/${username}/repos`, {
            headers: {
                'Authorization': `token ${this.token}`,
                'Accept': 'application/vnd.github.v3+json'
            }
        });
        return response.json();
    }

    async createRepository(repoName) {
        // VULNERABLE: Another hardcoded token variant
        const token = "ghp_ExAmPlEtOkEn1234567890aBcDeFgHiJkL";

        const response = await fetch(`${this.apiUrl}/user/repos`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${token}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ name: repoName, private: true })
        });
        return response.json();
    }
}

/**
 * VULNERABLE: Configuration object with multiple tokens
 */
const config = {
    github: {
        // VULNERABLE: Classic PAT
        personalToken: "ghp_0987654321ZyXwVuTsRqPoNmLkJiHgFeDcBa",
        // VULNERABLE: OAuth App token
        oauthToken: "gho_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij",
        // VULNERABLE: GitHub App token
        appToken: "ghs_abcdefghijklmnopqrstuvwxyz1234567890AB"
    },
    apiEndpoint: "https://api.github.com"
};

/**
 * VULNERABLE: Token in environment-like object
 */
const environment = {
    GITHUB_TOKEN: "ghp_ThisIsAHardcodedTokenForTesting123456",
    GITHUB_API_URL: "https://api.github.com",
    // VULNERABLE: Another token format
    GH_TOKEN: "ghp_AnotherExampleToken1234567890abcdefgh"
};

/**
 * VULNERABLE: Inline token usage
 */
async function fetchUserData(username) {
    // VULNERABLE: Token directly in fetch call
    const response = await fetch(`https://api.github.com/users/${username}`, {
        headers: {
            'Authorization': 'token ghp_InlineTokenExample1234567890abcdef'
        }
    });
    return response.json();
}

// VULNERABLE: Tokens in comments (sometimes left by developers)
// Production token: ghp_ProdTokenShouldNotBeHere1234567890
// Dev token: ghp_DevTokenAlsoNotSecure0987654321abcd
// Legacy token: ghp_OldTokenStillActive1234567890XyZ

module.exports = {
    GitHubClient,
    config,
    GITHUB_TOKEN
};
