import { render, screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { ActualFindings } from './ActualFindings';
import fixture from '../test/plan-demo.json';
import { validCatalog } from '../services/publicFindings';
it('renders only validated projected fields and explicit provenance limitations', () => {
  const value: unknown=fixture.findings;
  if(!validCatalog(value)) throw Error('Invalid fixture');
  render(<ActualFindings catalog={value}/>);
  expect(screen.getByRole('heading',{name:'Analyzer findings'})).toBeVisible();
  expect(screen.getAllByText(value.findings[0].control_id).length).toBeGreaterThan(0);
  expect(screen.getByText(/Context, freshness and authenticity: UNKNOWN/)).toBeVisible();
  expect(screen.queryByText('aws_s3_bucket.example')).not.toBeInTheDocument();
});
