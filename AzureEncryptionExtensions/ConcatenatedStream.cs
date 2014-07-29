// /*
//  Copyright (c) Stefan Gordon
//  All Rights Reserved
//  Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
//  License. You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
// 
//  THIS CODE IS PROVIDED ON AN *AS IS* BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED,
//  INCLUDING WITHOUT LIMITATION ANY IMPLIED WARRANTIES OR CONDITIONS OF TITLE, FITNESS FOR A PARTICULAR PURPOSE,
//  MERCHANTABLITY OR NON-INFRINGEMENT.
// 
//  See the Apache 2 License for the specific language governing permissions and limitations under the License.
//  */

#region

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

#endregion

namespace AzureEncryptionExtensions
{
    public class ConcatenatedStream : Stream
    {
        private readonly Queue<Stream> streams;
        private long position;

        public ConcatenatedStream(params Stream[] streams)
        {
            this.streams = new Queue<Stream>(streams);
        }

        public override void Flush()
        {
            throw new NotSupportedException();
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            if (streams.Count == 0) return 0;

            var read = streams.Peek().Read(buffer, offset, count);

            int totalRead = read;
            position += read;

            while (read == 0 || totalRead < count)
            {
                var stream = streams.Dequeue();
                stream.Dispose();

                if (streams.Count == 0) return totalRead;

                read = streams.Peek().Read(buffer, offset + read, count - totalRead);
                totalRead += read;
            } 
          
            return totalRead;
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        public override bool CanRead
        {
            get
            {                
                // Clean out any left over empty stream
                while (streams.Count != 0 && !streams.Peek().CanRead)
                {
                    streams.Dequeue();
                }

                return streams.Count != 0 && streams.Peek().CanRead;
            }
        }

        public override bool CanSeek
        {
            get { return false; }
        }

        public override bool CanWrite
        {
            get { return false; }
        }

        public override long Length
        {
            get { return streams.Sum(s => s.Length); }
        }

        public override long Position
        {
            get { return position; }
            set { throw new NotImplementedException(); }
        }
    }
}

