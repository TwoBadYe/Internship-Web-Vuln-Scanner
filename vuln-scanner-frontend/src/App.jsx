import React, { useState } from 'react';
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
} from '@chakra-ui/react';

function App() {
  const [target, setTarget] = useState('');
  const [scanOptions, setScanOptions] = useState([]);
  const toast = useToast();

  const handleScan = () => {
    if (!target.trim()) {
      toast({
        title: 'Target URL/IP is required',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    toast({
      title: 'Scan started',
      description: `Scanning ${target} for: ${scanOptions.join(', ') || 'default options'}...`,
      status: 'info',
      duration: 3000,
      isClosable: true,
    });

    // TODO: call backend API
  };

  const handleAdvanced = () => {
    if (!target.trim()) {
      toast({
        title: 'Target URL/IP is required',
        status: 'warning',
        duration: 3000,
        isClosable: true,
      });
      return;
    }

    toast({
      title: 'Advanced scan started',
      description: `Performing service fingerprinting and CVE lookup on ${target}...`,
      status: 'info',
      duration: 3000,
      isClosable: true,
    });

    // TODO: call advanced backend API
  };

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
                <Checkbox value="SQL Injection">SQL Injection</Checkbox>
                <Checkbox value="XSS">Cross-Site Scripting (XSS)</Checkbox>
                <Checkbox value="Open Ports">Open Ports</Checkbox>
                <Checkbox value="Directory Traversal">Directory Traversal</Checkbox>
                <Checkbox value="HTTP Headers">HTTP Security Headers</Checkbox>
                <Checkbox value="TLS/SSL">TLS/SSL Configuration</Checkbox>
                <Checkbox value="Robots.txt">Robots.txt</Checkbox>
                <Checkbox value="Clickjacking">Clickjacking Protection</Checkbox>
              </Stack>
            </CheckboxGroup>
          </FormControl>

          <Button colorScheme="teal" onClick={handleScan}>
            Start Exploits Scan
          </Button>

          <Button variant="outline" colorScheme="teal" onClick={handleAdvanced}>
            Start Service Scan
          </Button>
        </VStack>

        <Box mt={10}>
          <Heading size="md" mb={4}>Scan Results</Heading>
          <Text color="gray.500">No scan results yet.</Text>
        </Box>
      </Container>
    </Box>
  );
}

export default App;
