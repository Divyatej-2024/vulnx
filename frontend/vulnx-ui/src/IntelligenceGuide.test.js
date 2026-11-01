import { fireEvent, render, screen } from '@testing-library/react';
import IntelligenceGuide from './IntelligenceGuide';

test('explains the VulnX workflow and expands plain-language metric definitions', () => {
  render(<IntelligenceGuide />);

  expect(screen.getByRole('heading', { name: /turn vulnerability data into a clear next step/i })).toBeInTheDocument();
  expect(screen.getByText(/search by cve id or keyword/i)).toBeInTheDocument();

  fireEvent.click(screen.getByRole('button', { name: /explain the numbers/i }));

  expect(screen.getByRole('heading', { name: /what each number actually means/i })).toBeInTheDocument();
  expect(screen.getByText(/CVSS — How serious could it be\?/i)).toBeInTheDocument();
  expect(screen.getByText(/EPSS — How likely is exploitation\?/i)).toBeInTheDocument();
  expect(screen.getByText(/CISA KEV — Is exploitation confirmed\?/i)).toBeInTheDocument();
  expect(screen.getByText(/does not scan your network/i)).toBeInTheDocument();
});
