import React, { useState, useEffect } from 'react';
import axios from 'axios';
import {
  Box,
  Button,
  Input,
  VStack,
  Heading,
  FormControl,
  FormLabel,
  Checkbox,
  CheckboxGroup,
  Stack,
  useToast,
  Text,
  Container,
  Spinner,
  Select,
} from '@chakra-ui/react';

function App() {
  const [target, setTarget] = useState('');
  const [scanOptions, setScanOptions] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const toast = useToast();

  // List of scan options for checkboxes
  const optionList = [
    'XSS',
    'SQL Injection',
    'Open Ports',
    'Directory & File Enumeration',
    'HTTP Security Headers',
    'TLS/SSL Configuration',
    'Robots.txt',
    'Clickjacking Protection',
  ];

  // Derive unique vulnerability types from results for filter dropdown
  const vulnTypes = results
    ? Array.from(new Set(results.map(f => f.vulnerability)))
    : [];

  // Debug state
  useEffect(() => {
    console.log('Debug State:', { filter, vulnTypes, results });
  }, [filter, vulnTypes, results]);

  const handleScan = async () => {
    if (!target.trim()) {
      toast({ title: 'Target URL/IP is required', status: 'warning', duration: 3000, isClosable: true });
      return;
    }
    try {
      toast({ title: 'Scan started', description: `Scanning ${target}...`, status: 'info', duration: 3000, isClosable: true });
      setLoading(true);
      setFilter('');
      setResults(null);
      const resp = await axios.post('http://localhost:8000/scan/scan/basic', {
        target,
        options: scanOptions,
      });
      setScanId(resp.data.scan_id);
      setStatus(resp.data.status);
    } catch (error) {
      toast({ title: 'Error starting scan', description: error.message, status: 'error', duration: 3000, isClosable: true });
      setLoading(false);
    }
  };

  useEffect(() => {
    if (!scanId || status === 'done' || status === 'not_found') {
      if (status === 'done') fetchResults();
      setLoading(status === 'in_progress');
      return;
    }

    const interval = setInterval(async () => {
      try {
        const resp = await axios.get(`http://localhost:8000/scan/scan/${scanId}/status`);
        setStatus(resp.data.status);
      } catch (err) {
        toast({ title: 'Error fetching status', description: err.message, status: 'error', duration: 3000, isClosable: true });
        clearInterval(interval);
        setLoading(false);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, status]);

  const fetchResults = async () => {
    try {
      const resp = await axios.get(`http://localhost:8000/scan/scan/${scanId}/results`);
      setResults(resp.data.findings);
      setLoading(false);
    } catch (err) {
      toast({ title: 'Error fetching results', description: err.message, status: 'error', duration: 3000, isClosable: true });
      setLoading(false);
    }
  };

  // Filter results by exact vulnerability type
  const filteredResults = results
    ? results.filter(f => (filter ? f.vulnerability === filter : true))
    : [];

  return (
    <Box minH="100vh" bg="gray.50">
      <Box bg="teal.500" color="white" py={4} px={8}>
        <Heading size="lg">Web Vulnerability Scanner</Heading>
      </Box>

      <Container maxW="lg" mt={10}>
        <VStack spacing={6} align="stretch">
          <FormControl>
            <FormLabel>Target URL or IP</FormLabel>
            <Input
              placeholder="http://example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </FormControl>

          <FormControl>
            <FormLabel>Scan Options</FormLabel>
            <CheckboxGroup value={scanOptions} onChange={setScanOptions}>
              <Stack spacing={2}>
                {optionList.map(opt => (
                  <Checkbox key={opt} value={opt}>{opt}</Checkbox>
                ))}
              </Stack>
            </CheckboxGroup>
          </FormControl>

          <Button colorScheme="teal" onClick={handleScan} isDisabled={loading}>
            {loading && status === 'in_progress' && <Spinner size="sm" mr={2} />}
            Start Exploits Scan
          </Button>
        </VStack>

        <Box mt={10}>
          <Heading size="md" mb={4}>Scan Results</Heading>
          {!scanId && <Text color="gray.500">No scan initiated yet.</Text>}
          {loading && <Text color="gray.500">Scanning...</Text>}
          {status === 'not_found' && <Text color="red.500">Scan ID not found.</Text>}

          {/* Vulnerability Filter */}
          {results && results.length > 0 && (
            <FormControl mb={4}>
              <FormLabel>Filter by Vulnerability</FormLabel>
              <Select placeholder="All" value={filter} onChange={e => setFilter(e.target.value)}>
                <option value="">All</option>
                {vulnTypes.map(type => <option key={type} value={type}>{type}</option>)}
              </Select>
            </FormControl>
          )}

          {/* Display filtered results */}
          {status === 'done' && (
            filteredResults.length > 0 ? (
              filteredResults.map((f, i) => (
                <Box key={i} p={4} bg="white" shadow="sm" rounded="md" mb={2}>
                  <Text><strong>{f.vulnerability}</strong> on <em>{f.parameter || '—'}</em></Text>
                  <Text mt={2}>{f.payloads.join(', ')}</Text>
                </Box>
              ))
            ) : (
              <Text color="gray.500">No findings for selected filter.</Text>
            )
          )}
        </Box>
      </Container>
    </Box>
  );
}

export default App;
