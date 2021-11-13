#https://stackoverflow.com/questions/24277488/in-python-how-to-capture-the-stdout-from-a-c-shared-library-to-a-variable

import os
import sys
import threading
import time

#sys.stdout.write = lambda z: os.write(sys.stdout.fileno(),z.encode(sys.stdout.encoding) if hasattr(z,'encode') else z)
#sys.stdout.write = lambda z: os.write(sys.stdout.fileno(),z)

class OutputGrabber(object):
    """
    Class used to grab standard output or another stream.
    """
    escape_char = bytes.fromhex("F0FF")

    def __init__(self, stream=None, threaded=False):
        self.origstream = stream
        self.threaded = threaded
        if self.origstream is None:
            self.origstream = sys.stdout
        self.origstreamfd = self.origstream.fileno()
        self.captured:bytes = b''
        # Create a pipe so the stream can be captured:
        self.pipe_out, self.pipe_in = os.pipe()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, type, value, traceback):
        self.stop()

    def start(self):
        """
        Start capturing the stream data.
        """
        self.captured = b""
        # Save a copy of the stream:
        self.streamfd = os.dup(self.origstreamfd)
        # Replace the original stream with our write pipe:
        os.dup2(self.pipe_in, self.origstreamfd)
        if self.threaded:
            # Start thread that will read the stream:
            self.workerThread = threading.Thread(target=self.readOutput)
            self.workerThread.start()
            # Make sure that the thread is running and os.read() has executed:
            time.sleep(0.01)

    def stop(self):
        """
        Stop capturing the stream data and save the text in `captured`.
        """
        # Print the escape character to make the readOutput method stop:
        os.write(self.origstream.fileno(), self.escape_char)

        # Flush the stream to make sure all our data goes in before
        # the escape character:
        self.origstream.flush()
        if self.threaded:
            # wait until the thread finishes so we are sure that
            # we have until the last character:
            self.workerThread.join()
        else:
            self.readOutput()
        # Close the pipe:
        os.close(self.pipe_in)
        os.close(self.pipe_out)
        # Restore the original stream:
        os.dup2(self.streamfd, self.origstreamfd)
        # Close the duplicate stream:
        os.close(self.streamfd)

    def readOutput(self):
        """
        Read the stream data
        and save in `captured`.
        """
        while True:
            char = os.read(self.pipe_out, 4096)
            if not char or char.endswith(self.escape_char):
                if char:
                    self.captured += char[:-2]
                break
            self.captured += char