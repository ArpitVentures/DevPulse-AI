const TAVILY_API_URL = 'https://api.tavily.com/search';
const REQUEST_TIMEOUT_MS = 20_000;

interface TavilyResult {
  title?: string;
  url?: string;
  content?: string;
}

interface TavilyResponse {
  results?: TavilyResult[];
  answer?: string;
  detail?: {
    error?: string;
  };
}

export interface SecurityResearch {
  query: string;
  answer: string;
  sources: Array<{
    title: string;
    url: string;
    content: string;
  }>;
}

export async function researchSecurityIssue(
  query: string,
): Promise<SecurityResearch> {
  const apiKey = process.env.TAVILY_API_KEY;

  if (!apiKey) {
    throw new Error('TAVILY_API_KEY is not configured.');
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(TAVILY_API_URL, {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        query,
        search_depth: 'advanced',
        topic: 'general',
        max_results: 5,
        include_answer: false,
        include_raw_content: false,
      }),
      signal: controller.signal,
    });

    let data: TavilyResponse;

    try {
      data = (await response.json()) as TavilyResponse;
    } catch {
      throw new Error('Tavily returned an invalid response.');
    }

    if (!response.ok) {
      throw new Error(
        `Tavily API request failed with status ${response.status}.`,
      );
    }

    const sources = (data.results ?? [])
      .filter(
        (
          result,
        ): result is Required<
          Pick<TavilyResult, 'title' | 'url' | 'content'>
        > =>
          typeof result.title === 'string' &&
          typeof result.url === 'string' &&
          typeof result.content === 'string' &&
          result.title.trim().length > 0 &&
          result.url.trim().length > 0 &&
          result.content.trim().length > 0,
      )
      .map((result) => ({
        title: result.title,
        url: result.url,
        content: result.content,
      }));

    return {
      query,
      answer: typeof data.answer === 'string' ? data.answer : '',
      sources,
    };
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error('Tavily security research request timed out.');
    }

    throw error;
  } finally {
    clearTimeout(timeout);
  }
}
