import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { LoginPage } from '../../pages/LoginPage';

vi.mock('../../auth/AuthContext', () => ({
  useAuth: () => ({ login: vi.fn(), isLoading: false }),
}));

describe('unauthenticated TraceSleuth branding', () => {
  it('shows the independent product identity before sign-in', () => {
    render(<LoginPage />);
    expect(screen.getByRole('heading', { name: 'TraceSleuth' })).toBeInTheDocument();
    expect(screen.getByText('Packets tell the story. TraceSleuth finds the problem.')).toBeInTheDocument();
    expect(screen.queryByText('SD-WAN Triage')).not.toBeInTheDocument();
  });
});
