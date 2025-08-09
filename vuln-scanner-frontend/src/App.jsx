// src/App.jsx (or wherever your component lives)
import React, { useState, useEffect } from 'react';
import { Icon } from '@chakra-ui/react';
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
  IconButton,
  useColorMode,
} from '@chakra-ui/react';
import { motion } from 'framer-motion';
import { FaBug, FaSearch, FaMoon, FaSun, FaBolt } from 'react-icons/fa';

const MotionBox = motion(Box);

function App() {
  const API_BASE = 'http://localhost:8000/scan'; // <<-- centralize base URL here

  const [target, setTarget] = useState('');
  const [scanOptions, setScanOptions] = useState([]);
  const [scanId, setScanId] = useState(null);
  const [status, setStatus] = useState(null);
  const [results, setResults] = useState(null);
  const [loading, setLoading] = useState(false);
  const [filter, setFilter] = useState('');
  const toast = useToast();
  const { colorMode, toggleColorMode } = useColorMode();

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

  const vulnTypes = results ? Array.from(new Set(results.map(f => f.vulnerability))) : [];

  useEffect(() => {
    console.log('Debug State:', { filter, vulnTypes, results });
  }, [filter, vulnTypes, results]);

  const handleScan = async () => {
    if (!target.trim()) {
      toast({ title: 'Target URL/IP is required', status: 'warning', duration: 3000, isClosable: true });
      return;
    }
    toast({ title: 'Scan started', description: `Scanning ${target}...`, status: 'info', duration: 3000, isClosable: true });
    setLoading(true);
    setFilter('');
    setResults(null);

    try {
      // NOTE: endpoint -> `${API_BASE}/basic`
      const resp = await axios.post(`${API_BASE}/basic`, { target, options: scanOptions });
      setScanId(resp.data.scan_id);
      setStatus(resp.data.status);
    } catch (error) {
      toast({ title: 'Error', description: error?.response?.data || error.message, status: 'error', duration: 3000, isClosable: true });
      setLoading(false);
    }
  };

  // Handler for advanced service scan
  const handleAdvancedScan = async () => {
    if (!target.trim()) {
      toast({ title: 'Target URL/IP is required', status: 'warning', duration: 3000, isClosable: true });
      return;
    }
    toast({ title: 'Service scan started', description: `Fingerprinting ${target} and fetching CVE data...`, status: 'info', duration: 3000, isClosable: true });
    setLoading(true);
    setFilter('');
    setResults(null);

    try {
      // NOTE: endpoint -> `${API_BASE}/advanced`
      const resp = await axios.post(`${API_BASE}/advanced`, { target });
      setScanId(resp.data.scan_id);
      setStatus(resp.data.status);
    } catch (error) {
      toast({ title: 'Error', description: error?.response?.data || error.message, status: 'error', duration: 3000, isClosable: true });
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
        // NOTE: status endpoint -> `${API_BASE}/${scanId}/status`
        const resp = await axios.get(`${API_BASE}/${scanId}/status`);
        setStatus(resp.data.status);
      } catch (err) {
        console.error('Status poll failed', err);
        clearInterval(interval);
        setLoading(false);
      }
    }, 2000);
    return () => clearInterval(interval);
  }, [scanId, status]);

  const fetchResults = async () => {
    try {
      // NOTE: results endpoint -> `${API_BASE}/${scanId}/results`
      const resp = await axios.get(`${API_BASE}/${scanId}/results`);
      setResults(resp.data.findings);
      setLoading(false);
    } catch (err) {
      console.error('Fetch results failed', err);
      setLoading(false);
    }
  };

  const filteredResults = results ? results.filter(f => (filter ? f.vulnerability === filter : true)) : [];

  return (
    <Box minH="100vh" bgGradient={colorMode === 'light' ? 'linear(to-br, gray.50, gray.100)' : 'linear(to-br, gray.900, gray.800)'} py={10} color={colorMode === 'light' ? 'gray.800' : 'white'}>
      <Container maxW="3xl">
        <VStack spacing={6} textAlign="center">
          <Heading size="2xl" bgGradient="linear(to-r, teal.300, blue.500)" bgClip="text" lineHeight="1.2">
            <Icon as={FaBolt} boxSize={12} color={colorMode === 'light' ? 'teal.300' : 'teal.200'} mr={3} verticalAlign="middle" />
            Web Vulnerability Scanner
          </Heading>
          <Text fontSize="lg" color={colorMode === 'light' ? 'gray.600' : 'gray.300'}>
            Scan your web applications for common vulnerabilities
          </Text>
        </VStack>

        <MotionBox
          mt={10}
          p={8}
          rounded="2xl"
          shadow="2xl"
          bg={colorMode === 'light' ? 'whiteAlpha.800' : 'whiteAlpha.100'}
          backdropFilter="blur(10px)"
          initial={{ opacity: 0, y: 30 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
        >
          <VStack spacing={6}>
            <FormControl>
              <FormLabel>Target URL or IP</FormLabel>
              <Input
                placeholder="http://example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                bg={colorMode === 'light' ? 'white' : 'gray.700'}
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
            <Stack direction={["column", "row"]} spacing={4} w="full">
              <Button
                flex={1}
                colorScheme="teal"
                onClick={handleScan}
                isDisabled={loading}
              >
                {loading && status === 'in_progress' ? <Spinner size="sm" mr={2} /> : <FaSearch style={{ marginRight: 8 }} />}
                {loading ? 'Scanning...' : 'Start Scan'}
              </Button>
              <Button
                flex={1}
                variant="outline"
                colorScheme="orange"
                onClick={handleAdvancedScan}
                isDisabled={loading}
              >
                🔍 Service Scan
              </Button>
            </Stack>
          </VStack>
        </MotionBox>

        {status === 'done' && results && (
          <Box mt={10}>
            <Heading size="lg" mb={4}>Results</Heading>
            <FormControl mb={4}>
              <FormLabel>Filter by vulnerability</FormLabel>
              <Select
                value={filter}
                onChange={e => setFilter(e.target.value)}
                bg={colorMode === 'light' ? 'white' : 'gray.700'}
              >
                <option value="">All</option>
                {vulnTypes.map(type => (
                  <option key={type} value={type}>{type}</option>
                ))}
              </Select>
            </FormControl>
            <VStack spacing={4}>
              {filteredResults.map((f, i) => (
                <MotionBox
                  key={i}
                  bg={colorMode === 'light' ? 'gray.100' : 'gray.700'}
                  p={4}
                  rounded="md"
                  shadow="md"
                  whileHover={{ scale: 1.02 }}
                  w="full"
                >
                  <Text fontWeight="bold">
                    <FaBug style={{ marginRight: 8, display: 'inline' }} />
                    {f.vulnerability} – <em>{f.parameter || '—'}</em>
                  </Text>
                  <Text mt={2} fontSize="sm" color={colorMode === 'light' ? 'gray.600' : 'gray.300'}>
                    {Array.isArray(f.payloads) ? f.payloads.join(', ') : String(f.payloads)}
                  </Text>
                </MotionBox>
              ))}
            </VStack>
          </Box>
        )}


        {/* Footer with Dark/Light Toggle */}
        <Box mt={12} py={4} textAlign="center">
          <IconButton
            aria-label="Toggle Dark Mode"
            icon={colorMode === 'light' ? <FaMoon /> : <FaSun />}
            onClick={toggleColorMode}
            fontSize="24px"
          />
          <Text fontSize="sm" mt={2} color={colorMode === 'dark' ? 'gray.600' : 'gray.400'}>
            {new Date().getFullYear()} Web Vulnerability Scanner
          </Text>
        </Box>
      </Container>
    </Box>
  );
}

export default App;
