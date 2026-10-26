import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import axios from 'axios';
import App from './App';

jest.mock('axios', () => ({ get: jest.fn() }));

beforeEach(() => {
  window.localStorage.clear();
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: jest.fn().mockImplementation((query) => ({
      matches: false,
      media: query,
      onchange: null,
      addListener: jest.fn(),
      removeListener: jest.fn(),
      addEventListener: jest.fn(),
      removeEventListener: jest.fn(),
      dispatchEvent: jest.fn(),
    })),
  });

  axios.get.mockImplementation((url) => {
    if (url.endsWith('/summary')) {
      return Promise.resolve({
        data: {
          total: 1,
          critical: 0,
          high: 1,
          latest_published: '2025-01-01T00:00:00',
        },
      });
    }

    if (url.includes('/vulns/')) {
      return Promise.resolve({
        data: {
          cve_id: 'CVE-2025-1234',
          title: 'CVE-2025-1234',
          description: 'A sample vulnerability for UI testing.',
          published_date: '2025-01-01T00:00:00',
          cvss_v3: 7.5,
          source: {},
        },
      });
    }

    return Promise.resolve({
      data: {
        vulns: [{
          cve_id: 'CVE-2025-1234',
          title: 'CVE-2025-1234',
          description: 'A sample vulnerability for UI testing.',
          published_date: '2025-01-01T00:00:00',
          cvss_v3: 7.5,
          score: 0.75,
        }],
        total: 1,
        limit: 12,
        offset: 0,
      },
    });
  });
});

afterEach(() => {
  jest.clearAllMocks();
});

test('renders the dashboard and vulnerability data returned by the API', async () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /I understand — continue/i }));

  expect(screen.getByRole('heading', { name: /vulnerability overview/i })).toBeInTheDocument();
  expect(await screen.findByRole('row', { name: /CVE-2025-1234/i })).toBeInTheDocument();
  expect(screen.getByText('Tracked vulnerabilities')).toBeInTheDocument();
  expect(screen.getByText('High severity')).toBeInTheDocument();

  await waitFor(() => {
    expect(axios.get).toHaveBeenCalledWith('/api/v1/vulns', {
      params: { limit: 12, offset: 0 },
    });
    expect(axios.get).toHaveBeenCalledWith('/api/v1/summary');
  });
});

test('opens and displays vulnerability details when a result is selected', async () => {
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /I understand — continue/i }));

  const row = await screen.findByRole('row', { name: /CVE-2025-1234/i });
  fireEvent.click(row);

  expect(await screen.findByRole('dialog')).toBeInTheDocument();
  expect(screen.getByText('A sample vulnerability for UI testing.')).toBeInTheDocument();
  expect(axios.get).toHaveBeenCalledWith('/api/v1/vulns/CVE-2025-1234');
});


test('does not request dashboard data until consent is acknowledged', async () => {
  render(<App />);
  expect(axios.get).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole('button', { name: /I understand — continue/i }));
  await waitFor(() => expect(axios.get).toHaveBeenCalled());
});

test('shows a clear waiting state when the API has no feed data yet', async () => {
  axios.get.mockRejectedValue(new Error('API temporarily unavailable'));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /I understand — continue/i }));

  expect(await screen.findByRole('heading', { name: /vulnerability data is not available yet/i })).toBeInTheDocument();
  expect(screen.getByText(/not exact NVD import progress/i)).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /check now/i })).toBeInTheDocument();
  expect(screen.getByText(/The feed will appear here when the API is ready/i)).toBeInTheDocument();
});


test('shows the waiting state when the API is reachable but the feed is still empty', async () => {
  axios.get.mockImplementation((url) => Promise.resolve({
    data: url.endsWith('/summary')
      ? { total: 0, critical: 0, high: 0, latest_published: null }
      : { vulns: [], total: 0, limit: 12, offset: 0 },
  }));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: /I understand — continue/i }));

  expect(await screen.findByRole('heading', { name: /vulnerability data is not available yet/i })).toBeInTheDocument();
  expect(screen.getByText(/not exact NVD import progress/i)).toBeInTheDocument();
});
