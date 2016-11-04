package org.apache.drill.exec.store.pcap;

/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */



import com.mapr.PacketDecoder;
import io.netty.buffer.DrillBuf;
import org.apache.drill.common.exceptions.ExecutionSetupException;
import org.apache.drill.common.exceptions.UserException;
import org.apache.drill.common.expression.SchemaPath;
import org.apache.drill.exec.exception.OutOfMemoryException;
import org.apache.drill.exec.ops.FragmentContext;
import org.apache.drill.exec.ops.OperatorContext;
import org.apache.drill.exec.physical.impl.OutputMutator;
import org.apache.drill.exec.store.AbstractRecordReader;
import org.apache.drill.exec.store.dfs.DrillFileSystem;
import org.apache.drill.exec.vector.complex.impl.VectorContainerWriter;
import org.apache.drill.exec.vector.complex.writer.BaseWriter;
import org.apache.hadoop.fs.FSDataInputStream;
import org.apache.hadoop.fs.Path;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;

public class PCAPRecordReader extends AbstractRecordReader {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(PCAPRecordReader.class);
    private static final int MAX_RECORDS_PER_BATCH = 8096;

    private String inputPath;
    private BufferedReader reader;
    private DrillBuf buffer;
    private VectorContainerWriter writer;
    private PCAPFormatPlugin.PCAPFormatConfig config;
    private int lineCount;
    private PacketDecoder pd;
    private FSDataInputStream fsStream;


    public PCAPRecordReader(FragmentContext fragmentContext, String inputPath, DrillFileSystem fileSystem,
                            List<SchemaPath> columns, PCAPFormatPlugin.PCAPFormatConfig pcapFormatConfig)
        throws OutOfMemoryException {
        try {
            this.fsStream = fileSystem.open(new Path(inputPath));
            this.inputPath = inputPath;
            this.lineCount = 0;
            this.reader = new BufferedReader(new InputStreamReader(fsStream.getWrappedStream(), "UTF-8"));
            this.config = config;
            this.buffer = fragmentContext.getManagedBuffer();
            this.buffer = fragmentContext.getManagedBuffer();

        }
        catch ( Exception e) {
            logger.debug("PCAP Plugin:" + e.getMessage());
        }
    }


    public void setup(final OperatorContext context, final OutputMutator output) throws ExecutionSetupException {
        this.writer = new VectorContainerWriter(output);
        try {
            this.pd = new PacketDecoder(this.fsStream.getWrappedStream());
        } catch (java.io.IOException e){
            throw UserException.dataReadError(e).build(logger);
        }
    }

    public int next() {
        this.writer.allocate();
        this.writer.reset();
        int recordCount = 0;

        try {
            com.mapr.PacketDecoder.Packet p;

            p = pd.nextPacket();
            while( p != null ){
                BaseWriter.MapWriter map = this.writer.rootAsMap();
                this.writer.setPosition(recordCount);
                map.start();

                //Get the protocol
                String protocol = "UNK";
                if( p.isTcpPacket() ){
                    protocol = "TCP";
                } else if( p.isUdpPacket()) {
                    protocol = "UDP";
                }

                String fieldName  = "Protocol";
                String fieldValue = protocol;
                byte[] bytes = fieldValue.getBytes("UTF-8");
                this.buffer.setBytes(0, bytes, 0, bytes.length);
                map.varChar(fieldName).writeVarChar(0, bytes.length, buffer);

                fieldName  = "FmIP";
                fieldValue = p.getEthernetSource().toString();
                bytes = fieldValue.getBytes("UTF-8");
                this.buffer.setBytes(0, bytes, 0, bytes.length);
                map.varChar(fieldName).writeVarChar(0, bytes.length, buffer);

                fieldName  = "ToIP";
                fieldValue = p.getEthernetDestination().toString();
                bytes = fieldValue.getBytes("UTF-8");
                this.buffer.setBytes(0, bytes, 0, bytes.length);
                map.varChar(fieldName).writeVarChar(0, bytes.length, buffer);

                fieldName = "PacketLength";
                int packetLength = p.getPacketLength();
                map.integer(fieldName).writeInt(packetLength);

                fieldName = "Timestamp";
                long ts = p.getTimestamp();
                map.timeStamp(fieldName).writeTimeStamp(ts);

                map.end();
                p = pd.nextPacket();
                recordCount++;
            }

            this.writer.setValueCount(recordCount);
            return recordCount;

        } catch ( final Exception e ) {
            throw UserException.dataReadError(e).build(logger);
        }
    }

    public void close() throws Exception {
        this.reader.close();
    }

}
