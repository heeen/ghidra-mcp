/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.xebyte.core.services;

import com.xebyte.core.ProgramProvider;
import com.xebyte.core.ThreadingStrategy;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

import java.util.*;

/**
 * Shared service for data type operations.
 *
 * Handles creation, modification, querying, and deletion of data types
 * (structs, enums, unions, typedefs, arrays, pointers). All write operations
 * use {@link ThreadingStrategy#executeWrite} for proper transaction management.
 */
public class DataTypeService extends BaseService {

    public DataTypeService(ProgramProvider programProvider, ThreadingStrategy threadingStrategy) {
        super(programProvider, threadingStrategy);
    }

    // =========================================================================
    // CREATE OPERATIONS
    // =========================================================================

    /**
     * Create a structure data type.
     * Endpoint: /create_struct
     *
     * @param name       structure name
     * @param fieldsJson JSON array of field objects: [{"name":"f1","type":"int"}, ...]
     */
    public String createStruct(String name, String fieldsJson) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }
        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return "{\"error\": \"Fields array is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create structure", () -> {
                DataTypeManager dtm = program.getDataTypeManager();

                // Check if struct already exists
                Iterator<DataType> iter = dtm.getAllDataTypes();
                while (iter.hasNext()) {
                    DataType dt = iter.next();
                    if (dt.getName().equals(name) && dt instanceof Structure) {
                        return "{\"error\": \"Structure '" + name + "' already exists\"}";
                    }
                }

                // Create new structure
                StructureDataType struct = new StructureDataType(name, 0);

                // Parse fields JSON: [{"name": "field1", "type": "int"}, ...]
                List<Map<String, String>> fields = parseFieldsJson(fieldsJson);

                for (Map<String, String> field : fields) {
                    String fieldName = field.get("name");
                    String fieldType = field.get("type");

                    if (fieldName == null || fieldType == null) {
                        continue;
                    }

                    DataType fieldDataType = resolveDataType(dtm, fieldType);
                    if (fieldDataType == null) {
                        return "{\"error\": \"Unknown field type: " + fieldType + "\"}";
                    }

                    String offsetStr = field.get("offset");
                    if (offsetStr != null) {
                        try {
                            int offset = Integer.parseInt(offsetStr);
                            if (offset >= 0) {
                                // Grow struct if needed
                                while (struct.getLength() < offset + fieldDataType.getLength()) {
                                    struct.add(ByteDataType.dataType, "_pad", null);
                                }
                                struct.replaceAtOffset(offset, fieldDataType,
                                    fieldDataType.getLength(), fieldName, null);
                                continue;
                            }
                        } catch (NumberFormatException ignored) {
                        }
                    }

                    struct.add(fieldDataType, fieldName, null);
                }

                // Add to data type manager
                dtm.addDataType(struct, null);

                return "{\"success\": true, \"message\": \"Created structure '" + name +
                       "' with " + fields.size() + " fields\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create an enumeration data type.
     * Endpoint: /create_enum
     *
     * @param name       enumeration name
     * @param valuesJson JSON object of name-value pairs: {"NAME1": 0, "NAME2": 1}
     * @param size       size in bytes (1, 2, 4, or 8)
     */
    public String createEnum(String name, String valuesJson, int size) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Enumeration name is required\"}";
        }

        if (valuesJson == null || valuesJson.isEmpty()) {
            return "{\"error\": \"Values JSON is required\"}";
        }

        if (size != 1 && size != 2 && size != 4 && size != 8) {
            return "{\"error\": \"Invalid size. Must be 1, 2, 4, or 8 bytes\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Enumeration: " + name, () -> {
                Map<String, Long> values = parseEnumValuesJson(valuesJson);

                if (values.isEmpty()) {
                    return "{\"error\": \"No valid enum values provided\"}";
                }

                DataTypeManager dtm = program.getDataTypeManager();

                // Check if enum already exists
                DataType existingType = dtm.getDataType("/" + name);
                if (existingType != null) {
                    return "{\"error\": \"Enumeration with name '" + name + "' already exists\"}";
                }

                EnumDataType enumDt = new EnumDataType(name, size);

                for (Map.Entry<String, Long> entry : values.entrySet()) {
                    enumDt.add(entry.getKey(), entry.getValue());
                }

                dtm.addDataType(enumDt, null);

                return "{\"success\": true, \"message\": \"Created enumeration '" + name +
                       "' with " + values.size() + " values, size: " + size + " bytes\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating enumeration: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a union data type.
     * Endpoint: /create_union
     *
     * @param name       union name
     * @param fieldsJson JSON array of field objects: [{"name":"f1","type":"int"}, ...]
     */
    public String createUnion(String name, String fieldsJson) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Union name is required\"}";
        }

        if (fieldsJson == null || fieldsJson.isEmpty()) {
            return "{\"error\": \"Fields JSON is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Union: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                UnionDataType union = new UnionDataType(name);

                List<Map<String, String>> fields = parseFieldsJson(fieldsJson);

                if (fields.isEmpty()) {
                    return "{\"error\": \"No valid fields provided\"}";
                }

                int addedCount = 0;
                for (Map<String, String> field : fields) {
                    String fieldName = field.get("name");
                    String fieldType = field.get("type");

                    if (fieldName != null && fieldType != null) {
                        DataType dt = resolveDataType(dtm, fieldType);
                        if (dt != null) {
                            union.add(dt, fieldName, null);
                            addedCount++;
                        }
                    }
                }

                dtm.addDataType(union, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Union '" + name +
                       "' created with " + addedCount + " fields\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating union: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a typedef (type alias).
     * Endpoint: /create_typedef
     */
    public String createTypedef(String name, String baseType) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (name == null || name.isEmpty()) {
            return "{\"error\": \"Typedef name is required\"}";
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Typedef: " + name, () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType base = resolveDataType(dtm, baseType);

                if (base == null) {
                    return "{\"error\": \"Base type not found: " + baseType + "\"}";
                }

                TypedefDataType typedef = new TypedefDataType(name, base);
                dtm.addDataType(typedef, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Typedef '" + name +
                       "' created as alias for '" + baseType + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating typedef: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create an array data type.
     * Endpoint: /create_array_type
     */
    public String createArrayType(String baseType, int length, String name) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        if (length <= 0) {
            return "{\"error\": \"Array length must be positive\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Array Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = resolveDataType(dtm, baseType);

                if (baseDataType == null) {
                    return "{\"error\": \"Base data type not found: " + baseType + "\"}";
                }

                ArrayDataType arrayType = new ArrayDataType(baseDataType, length, baseDataType.getLength());

                if (name != null && !name.isEmpty()) {
                    arrayType.setName(name);
                }

                DataType addedType = dtm.addDataType(arrayType, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Created array type: " +
                       addedType.getName() + " (" + baseType + "[" + length + "])\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating array type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Create a pointer data type.
     * Endpoint: /create_pointer_type
     */
    public String createPointerType(String baseType, String name) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (baseType == null || baseType.isEmpty()) {
            return "{\"error\": \"Base type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Create Pointer Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType baseDataType = null;

                if ("void".equals(baseType)) {
                    baseDataType = dtm.getDataType("/void");
                    if (baseDataType == null) {
                        baseDataType = VoidDataType.dataType;
                    }
                } else {
                    baseDataType = resolveDataType(dtm, baseType);
                }

                if (baseDataType == null) {
                    return "{\"error\": \"Base data type not found: " + baseType + "\"}";
                }

                PointerDataType pointerType = new PointerDataType(baseDataType);

                if (name != null && !name.isEmpty()) {
                    pointerType.setName(name);
                }

                DataType addedType = dtm.addDataType(pointerType, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Created pointer type: " +
                       addedType.getName() + " (" + baseType + "*)\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error creating pointer type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // APPLY / MODIFY / DELETE OPERATIONS
    // =========================================================================

    /**
     * Apply a data type at an address.
     * Endpoint: /apply_data_type
     */
    public String applyDataType(String addressStr, String typeName, boolean clearExisting) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (addressStr == null || addressStr.isEmpty()) {
            return "{\"error\": \"Address is required\"}";
        }
        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        Address addr = parseAddress(program, addressStr);
        if (addr == null) {
            return "{\"error\": \"Invalid address: " + addressStr + "\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Apply data type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = resolveDataType(dtm, typeName);

                if (dataType == null) {
                    return "{\"error\": \"Data type not found: " + typeName + "\"}";
                }

                Listing listing = program.getListing();

                if (clearExisting) {
                    listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);
                }

                try {
                    listing.createData(addr, dataType);
                    return "{\"success\": true, \"message\": \"Applied '" + typeName + "' at " + addressStr + "\"}";
                } catch (Exception e) {
                    return "{\"error\": \"Failed to apply data type - " + escapeJson(e.getMessage()) + "\"}";
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Add a field to an existing structure.
     * Endpoint: /add_struct_field
     *
     * @param offset if negative, field is appended to end
     */
    public String addStructField(String structName, String fieldName, String fieldType, int offset) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        if (fieldType == null || fieldType.isEmpty()) {
            return "{\"error\": \"Field type is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Add Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataType newFieldType = resolveDataType(dtm, fieldType);

                if (newFieldType == null) {
                    return "{\"error\": \"Field data type not found: " + fieldType + "\"}";
                }

                if (offset >= 0) {
                    struct.insertAtOffset(offset, newFieldType, newFieldType.getLength(), fieldName, null);
                } else {
                    struct.add(newFieldType, fieldName, null);
                }

                return "{\"success\": true, \"message\": \"Added field '" + fieldName +
                       "' to structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error adding struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Modify a field in an existing structure.
     * Endpoint: /modify_struct_field
     */
    public String modifyStructField(String structName, String fieldName, String newType, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Modify Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent[] components = struct.getDefinedComponents();
                DataTypeComponent targetComponent = null;

                for (DataTypeComponent component : components) {
                    if (fieldName.equals(component.getFieldName())) {
                        targetComponent = component;
                        break;
                    }
                }

                if (targetComponent == null) {
                    return "{\"error\": \"Field '" + fieldName + "' not found in structure '" + structName + "'\"}";
                }

                if (newType != null && !newType.isEmpty()) {
                    DataType newDataType = resolveDataType(dtm, newType);
                    if (newDataType == null) {
                        return "{\"error\": \"New data type not found: " + newType + "\"}";
                    }
                    struct.replace(targetComponent.getOrdinal(), newDataType, newDataType.getLength());
                }

                if (newName != null && !newName.isEmpty()) {
                    targetComponent = struct.getComponent(targetComponent.getOrdinal());
                    targetComponent.setFieldName(newName);
                }

                return "{\"success\": true, \"message\": \"Modified field '" + fieldName +
                       "' in structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error modifying struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Remove a field from an existing structure.
     * Endpoint: /remove_struct_field
     */
    public String removeStructField(String structName, String fieldName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Structure name is required\"}";
        }

        if (fieldName == null || fieldName.isEmpty()) {
            return "{\"error\": \"Field name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Remove Struct Field", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, structName);

                if (dataType == null) {
                    return "{\"error\": \"Structure not found: " + structName + "\"}";
                }

                if (!(dataType instanceof Structure)) {
                    return "{\"error\": \"Data type '" + structName + "' is not a structure\"}";
                }

                Structure struct = (Structure) dataType;
                DataTypeComponent[] components = struct.getDefinedComponents();
                int targetOrdinal = -1;

                for (DataTypeComponent component : components) {
                    if (fieldName.equals(component.getFieldName())) {
                        targetOrdinal = component.getOrdinal();
                        break;
                    }
                }

                if (targetOrdinal == -1) {
                    return "{\"error\": \"Field '" + fieldName + "' not found in structure '" + structName + "'\"}";
                }

                struct.delete(targetOrdinal);

                return "{\"success\": true, \"message\": \"Removed field '" + fieldName +
                       "' from structure '" + structName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error removing struct field: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Delete a data type.
     * Endpoint: /delete_data_type
     */
    public String deleteDataType(String typeName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Delete Data Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType dataType = findDataTypeByName(dtm, typeName);

                if (dataType == null) {
                    return "{\"error\": \"Data type not found: " + typeName + "\"}";
                }

                boolean deleted = dtm.remove(dataType, null);
                if (deleted) {
                    return "{\"success\": true, \"message\": \"Data type '" + typeName + "' deleted\"}";
                } else {
                    return "{\"error\": \"Failed to delete data type '" + typeName + "'\"}";
                }
            });
        } catch (Exception e) {
            return "{\"error\": \"Error deleting data type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Clone/copy a data type with a new name.
     * Endpoint: /clone_data_type
     */
    public String cloneDataType(String sourceType, String newName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (sourceType == null || sourceType.isEmpty()) {
            return "{\"error\": \"Source type is required\"}";
        }

        if (newName == null || newName.isEmpty()) {
            return "{\"error\": \"New name is required\"}";
        }

        try {
            return threadingStrategy.executeWrite(program, "Clone Data Type", () -> {
                DataTypeManager dtm = program.getDataTypeManager();
                DataType source = findDataTypeByName(dtm, sourceType);

                if (source == null) {
                    return "{\"error\": \"Source data type not found: " + sourceType + "\"}";
                }

                DataType cloned = source.copy(dtm);
                cloned.setName(newName);

                dtm.addDataType(cloned, DataTypeConflictHandler.REPLACE_HANDLER);

                return "{\"success\": true, \"message\": \"Cloned '" + sourceType +
                       "' as '" + newName + "'\"}";
            });
        } catch (Exception e) {
            return "{\"error\": \"Error cloning data type: " + escapeJson(e.getMessage()) + "\"}";
        }
    }

    // =========================================================================
    // QUERY OPERATIONS (read-only)
    // =========================================================================

    /**
     * Search for data types by pattern.
     * Endpoint: /search_data_types
     */
    public String searchDataTypes(String pattern, int offset, int limit) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (pattern == null || pattern.isEmpty()) {
            return "{\"error\": \"Search pattern is required\"}";
        }

        List<String> matches = new ArrayList<>();
        DataTypeManager dtm = program.getDataTypeManager();

        Iterator<DataType> allTypes = dtm.getAllDataTypes();
        while (allTypes.hasNext()) {
            DataType dt = allTypes.next();
            String name = dt.getName();
            String path = dt.getPathName();

            if (name.toLowerCase().contains(pattern.toLowerCase()) ||
                path.toLowerCase().contains(pattern.toLowerCase())) {
                matches.add(name + " | Size: " + dt.getLength() + " | Path: " + path);
            }
        }

        Collections.sort(matches);
        return paginateList(matches, offset, limit);
    }

    /**
     * Validate if a data type exists.
     * Endpoint: /validate_data_type_exists
     */
    public String validateDataTypeExists(String typeName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return "{\"error\": \"No program loaded\"}";
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        try {
            DataTypeManager dtm = program.getDataTypeManager();
            DataType dt = findDataTypeByName(dtm, typeName);

            StringBuilder sb = new StringBuilder();
            sb.append("{\"exists\": ").append(dt != null);
            sb.append(", \"type_name\": \"").append(escapeJson(typeName)).append("\"");
            if (dt != null) {
                sb.append(", \"category\": \"").append(escapeJson(dt.getCategoryPath().getPath())).append("\"");
                sb.append(", \"size\": ").append(dt.getLength());
            }
            sb.append("}");
            return sb.toString();

        } catch (Exception e) {
            return "{\"error\": \"" + escapeJson(e.getMessage()) + "\"}";
        }
    }

    /**
     * Get the size of a data type.
     * Endpoint: /get_data_type_size
     */
    public String getDataTypeSize(String typeName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (typeName == null || typeName.isEmpty()) {
            return "{\"error\": \"Type name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = resolveDataType(dtm, typeName);

        if (dataType == null) {
            return "{\"error\": \"Data type not found: " + typeName + "\"}";
        }

        StringBuilder sb = new StringBuilder();
        sb.append("{\"type_name\": \"").append(escapeJson(dataType.getName())).append("\"");
        sb.append(", \"size\": ").append(dataType.getLength());
        sb.append(", \"alignment\": ").append(dataType.getAlignment());
        sb.append(", \"path\": \"").append(escapeJson(dataType.getPathName())).append("\"");
        sb.append("}");
        return sb.toString();
    }

    /**
     * Get the layout of a structure.
     * Endpoint: /get_struct_layout
     */
    public String getStructLayout(String structName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (structName == null || structName.isEmpty()) {
            return "{\"error\": \"Struct name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByName(dtm, structName);

        if (dataType == null) {
            return "{\"error\": \"Structure not found: " + structName + "\"}";
        }

        if (!(dataType instanceof Structure)) {
            return "{\"error\": \"Data type is not a structure: " + structName + "\"}";
        }

        Structure struct = (Structure) dataType;
        StringBuilder sb = new StringBuilder();

        sb.append("{\"name\": \"").append(escapeJson(struct.getName())).append("\"");
        sb.append(", \"size\": ").append(struct.getLength());
        sb.append(", \"alignment\": ").append(struct.getAlignment());
        sb.append(", \"fields\": [");

        DataTypeComponent[] components = struct.getDefinedComponents();
        for (int i = 0; i < components.length; i++) {
            if (i > 0) sb.append(", ");
            DataTypeComponent comp = components[i];
            sb.append("{\"offset\": ").append(comp.getOffset());
            sb.append(", \"size\": ").append(comp.getLength());
            sb.append(", \"type\": \"").append(escapeJson(comp.getDataType().getName())).append("\"");
            sb.append(", \"name\": \"").append(escapeJson(comp.getFieldName() != null ? comp.getFieldName() : "(unnamed)")).append("\"");
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    /**
     * Get all values in an enumeration.
     * Endpoint: /get_enum_values
     */
    public String getEnumValues(String enumName) {
        Program program = resolveProgram(null);
        if (program == null) {
            return programNotFoundError(null);
        }

        if (enumName == null || enumName.isEmpty()) {
            return "{\"error\": \"Enum name is required\"}";
        }

        DataTypeManager dtm = program.getDataTypeManager();
        DataType dataType = findDataTypeByName(dtm, enumName);

        if (dataType == null) {
            return "{\"error\": \"Enumeration not found: " + enumName + "\"}";
        }

        if (!(dataType instanceof ghidra.program.model.data.Enum)) {
            return "{\"error\": \"Data type is not an enumeration: " + enumName + "\"}";
        }

        ghidra.program.model.data.Enum enumType = (ghidra.program.model.data.Enum) dataType;
        StringBuilder sb = new StringBuilder();

        sb.append("{\"name\": \"").append(escapeJson(enumType.getName())).append("\"");
        sb.append(", \"size\": ").append(enumType.getLength());
        sb.append(", \"values\": [");

        String[] names = enumType.getNames();
        for (int i = 0; i < names.length; i++) {
            if (i > 0) sb.append(", ");
            String valueName = names[i];
            long value = enumType.getValue(valueName);
            sb.append("{\"name\": \"").append(escapeJson(valueName)).append("\"");
            sb.append(", \"value\": ").append(value);
            sb.append("}");
        }

        sb.append("]}");
        return sb.toString();
    }

    // =========================================================================
    // TYPE RESOLUTION HELPERS
    // =========================================================================

    /**
     * Resolve a data type by name with comprehensive fallback chain:
     * well-known aliases, direct DTM lookup, category search, arrays, pointers.
     */
    protected DataType resolveDataType(DataTypeManager dtm, String typeName) {
        if (typeName == null || typeName.isEmpty()) return null;

        // 1. Well-known C type aliases
        DataType wellKnown = resolveWellKnownType(typeName);
        if (wellKnown != null) return wellKnown;

        // 2. Direct lookup in root category
        DataType builtinType = dtm.getDataType("/" + typeName);
        if (builtinType != null) return builtinType;

        // 3. Lowercase version (handles "UINT" -> "/uint")
        DataType builtinTypeLower = dtm.getDataType("/" + typeName.toLowerCase());
        if (builtinTypeLower != null) return builtinTypeLower;

        // 4. Search all categories
        DataType dataType = findDataTypeByName(dtm, typeName);
        if (dataType != null) return dataType;

        // 5. Built-in type manager
        DataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
        Iterator<DataType> iter = builtIn.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dt = iter.next();
            if (dt.getName().equals(typeName) || dt.getName().equalsIgnoreCase(typeName)) {
                return dt;
            }
        }

        // 6. Array syntax: "type[count]"
        if (typeName.contains("[") && typeName.endsWith("]")) {
            int bracketPos = typeName.indexOf('[');
            String baseTypeName = typeName.substring(0, bracketPos);
            String countStr = typeName.substring(bracketPos + 1, typeName.length() - 1);

            try {
                int count = Integer.parseInt(countStr);
                DataType baseType = resolveDataType(dtm, baseTypeName);

                if (baseType != null && count > 0) {
                    return new ArrayDataType(baseType, count, baseType.getLength());
                }
            } catch (NumberFormatException e) {
                return null;
            }
        }

        // 7. Pointer syntax: "type*"
        if (typeName.endsWith("*")) {
            String baseTypeName = typeName.substring(0, typeName.length() - 1).trim();

            if (baseTypeName.equals("void") || baseTypeName.isEmpty()) {
                DataType voidType = dtm.getDataType("/void");
                return new PointerDataType(voidType != null ? voidType : VoidDataType.dataType);
            }

            DataType baseType = resolveDataType(dtm, baseTypeName);
            if (baseType != null) {
                return new PointerDataType(baseType);
            }

            // Default to void* if base type not found
            DataType voidType = dtm.getDataType("/void");
            return new PointerDataType(voidType != null ? voidType : VoidDataType.dataType);
        }

        return null;
    }

    /**
     * Map common C type names to Ghidra built-in DataType instances.
     */
    private DataType resolveWellKnownType(String typeName) {
        switch (typeName.toLowerCase()) {
            case "int":            return IntegerDataType.dataType;
            case "uint":           return UnsignedIntegerDataType.dataType;
            case "short":          return ShortDataType.dataType;
            case "ushort":         return UnsignedShortDataType.dataType;
            case "long":           return LongDataType.dataType;
            case "ulong":          return UnsignedLongDataType.dataType;
            case "longlong":
            case "long long":      return LongLongDataType.dataType;
            case "char":           return CharDataType.dataType;
            case "uchar":          return UnsignedCharDataType.dataType;
            case "float":          return FloatDataType.dataType;
            case "double":         return DoubleDataType.dataType;
            case "bool":
            case "boolean":        return BooleanDataType.dataType;
            case "void":           return VoidDataType.dataType;
            case "byte":           return ByteDataType.dataType;
            case "ubyte":          return UnsignedCharDataType.dataType;
            case "sbyte":          return SignedByteDataType.dataType;
            case "word":           return WordDataType.dataType;
            case "dword":          return DWordDataType.dataType;
            case "qword":          return QWordDataType.dataType;
            case "int8_t":
            case "int8":           return SignedByteDataType.dataType;
            case "uint8_t":
            case "uint8":          return ByteDataType.dataType;
            case "int16_t":
            case "int16":          return ShortDataType.dataType;
            case "uint16_t":
            case "uint16":         return UnsignedShortDataType.dataType;
            case "int32_t":
            case "int32":          return IntegerDataType.dataType;
            case "uint32_t":
            case "uint32":         return UnsignedIntegerDataType.dataType;
            case "int64_t":
            case "int64":          return LongLongDataType.dataType;
            case "uint64_t":
            case "uint64":         return UnsignedLongLongDataType.dataType;
            case "size_t":         return UnsignedIntegerDataType.dataType;
            case "unsigned int":   return UnsignedIntegerDataType.dataType;
            case "unsigned short": return UnsignedShortDataType.dataType;
            case "unsigned long":  return UnsignedLongDataType.dataType;
            case "unsigned char":  return UnsignedCharDataType.dataType;
            case "signed char":    return SignedByteDataType.dataType;
            default:               return null;
        }
    }

    /**
     * Find a data type by name in all categories (exact match, then case-insensitive).
     */
    private DataType findDataTypeByName(DataTypeManager dtm, String typeName) {
        // Direct lookup in root category
        DataType dt = dtm.getDataType("/" + typeName);
        if (dt != null) return dt;

        // Search all categories (exact match)
        Iterator<DataType> iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equals(typeName)) {
                return dataType;
            }
        }

        // Case-insensitive fallback
        iter = dtm.getAllDataTypes();
        while (iter.hasNext()) {
            DataType dataType = iter.next();
            if (dataType.getName().equalsIgnoreCase(typeName)) {
                return dataType;
            }
        }

        return null;
    }

    // =========================================================================
    // JSON PARSING HELPERS
    // =========================================================================

    /**
     * Parse a JSON array of field objects.
     * Format: [{"name":"f1","type":"int","offset":"0"}, ...]
     */
    private List<Map<String, String>> parseFieldsJson(String json) {
        List<Map<String, String>> fields = new ArrayList<>();

        json = json.trim();
        if (!json.startsWith("[") || !json.endsWith("]")) {
            return fields;
        }

        json = json.substring(1, json.length() - 1).trim();
        if (json.isEmpty()) {
            return fields;
        }

        // Split by matching braces
        int depth = 0;
        StringBuilder current = new StringBuilder();

        for (int i = 0; i < json.length(); i++) {
            char c = json.charAt(i);

            if (c == '{') {
                depth++;
                if (depth == 1) {
                    current = new StringBuilder();
                    continue;
                }
            } else if (c == '}') {
                depth--;
                if (depth == 0) {
                    Map<String, String> field = parseSimpleJsonObject("{" + current.toString() + "}");
                    if (!field.isEmpty()) {
                        fields.add(field);
                    }
                    continue;
                }
            }

            if (depth > 0) {
                current.append(c);
            }
        }

        return fields;
    }

    /**
     * Parse a simple flat JSON object into key-value pairs.
     */
    private Map<String, String> parseSimpleJsonObject(String json) {
        Map<String, String> result = new HashMap<>();

        json = json.trim();
        if (!json.startsWith("{") || !json.endsWith("}")) {
            return result;
        }

        json = json.substring(1, json.length() - 1).trim();

        for (String pair : json.split(",")) {
            String[] kv = pair.split(":", 2);
            if (kv.length == 2) {
                String key = kv[0].trim().replaceAll("^\"|\"$", "");
                String value = kv[1].trim().replaceAll("^\"|\"$", "");
                result.put(key, value);
            }
        }

        return result;
    }

    /**
     * Parse enum values from JSON format {"NAME1": value1, "NAME2": value2}.
     */
    private Map<String, Long> parseEnumValuesJson(String valuesJson) {
        Map<String, Long> values = new LinkedHashMap<>();

        try {
            String content = valuesJson.trim();
            if (content.startsWith("{")) {
                content = content.substring(1);
            }
            if (content.endsWith("}")) {
                content = content.substring(0, content.length() - 1);
            }

            String[] pairs = content.split(",");

            for (String pair : pairs) {
                String[] keyValue = pair.split(":");
                if (keyValue.length == 2) {
                    String key = keyValue[0].trim().replace("\"", "");
                    String valueStr = keyValue[1].trim();

                    try {
                        Long value = Long.parseLong(valueStr);
                        values.put(key, value);
                    } catch (NumberFormatException e) {
                        // Skip invalid values
                    }
                }
            }
        } catch (Exception e) {
            // Return empty map on parse error
        }

        return values;
    }
}
